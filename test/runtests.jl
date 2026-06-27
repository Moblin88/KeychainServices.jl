using KeychainServices
using Dates
using Test

# ── Helpers ────────────────────────────────────────────────────────────────────

secret_buf(s::String) = Base.SecretBuffer(s)

data_protection_available() = @static Sys.isapple() ? probe_data_protection_entitlement() : false

# ── Platform / type tests (no entitlement required) ───────────────────────────

@testset "KeychainServices.jl" begin

    @testset "Platform support" begin
        if Sys.isapple()
            @test add_item!    isa Function
            @test search_items isa Function
            @test copy_secret  isa Function
            @test update_item! isa Function
            @test delete_item! isa Function
        else
            item = GenericPasswordItem(service="svc", account="acct")
            @test_throws UnsupportedPlatformError add_item!(item, secret_buf("x"))
            @test_throws UnsupportedPlatformError search_items(item)
            @test_throws UnsupportedPlatformError copy_secret(item)
            @test_throws UnsupportedPlatformError delete_item!(item)
        end
    end

    @testset "Type API" begin
        @test GenericPasswordItem    <: AbstractKeychainItem
        @test DataProtectionKeychain <: KeychainTarget
        @test LoginKeychain          <: KeychainTarget
        @test FileKeychain           <: KeychainTarget
        @test AccessControlItem      isa DataType
    end

    @testset "GenericPasswordItem defaults" begin
        item = GenericPasswordItem(service="svc", account="acct")
        @test item.service     == "svc"
        @test item.account     == "acct"
        @test item.label       === nothing
        @test item.keychain    isa LoginKeychain
        @test item.created_at  === nothing
        @test item.updated_at  === nothing
    end

    @testset "Secret inputs — accepted types" begin
        item = GenericPasswordItem(service="svc", account="acct")
        @test_throws MethodError add_item!(item, 42)
        @test_throws MethodError add_item!(item, :symbol)
    end

    @testset "Synchronizable + ThisDeviceOnly validation" begin
        bad = GenericPasswordItem(
            service="svc", account="acct",
            synchronizable=true,
            accessible=:kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        )
        @test_throws KeychainOperationError pairs(bad)
    end

    @testset "Unsupported accessible value" begin
        bad = GenericPasswordItem(service="svc", account="acct", accessible=:kSecAttrBogus)
        @test_throws KeychainOperationError pairs(bad)
    end

    @testset "AccessControlItem — unsupported accessible value" begin
        ctrl = AccessControlItem(:kSecAttrBogus, AccessControlFlags.BiometryAny)
        item = GenericPasswordItem(service="svc", account="acct", access_control=ctrl)
        @test_throws KeychainOperationError pairs(item)
    end

    @testset "pairs protocol — LoginKeychain (default)" begin
        item  = GenericPasswordItem(service="svc", account="acct", label="lbl")
        attrs = Dict(pairs(item))
        @test attrs[:kSecClass]       == :kSecClassGenericPassword
        @test attrs[:kSecAttrService] == "svc"
        @test attrs[:kSecAttrAccount] == "acct"
        @test attrs[:kSecAttrLabel]   == "lbl"
        @test !haskey(attrs, :kSecUseDataProtectionKeychain)
        @test !haskey(attrs, :kSecUseKeychain)
    end

    @testset "pairs protocol — timestamps not included in query dict" begin
        item  = GenericPasswordItem(service="svc", account="acct",
                                    created_at=DateTime(2024,1,1), updated_at=DateTime(2024,1,2))
        attrs = Dict(pairs(item))
        @test !haskey(attrs, :kSecAttrCreationDate)
        @test !haskey(attrs, :kSecAttrModificationDate)
    end

    @testset "pairs protocol — DataProtectionKeychain" begin
        item  = GenericPasswordItem(service="svc", account="acct", keychain=DataProtectionKeychain())
        attrs = Dict(pairs(item))
        @test attrs[:kSecClass] == :kSecClassGenericPassword
        @test !haskey(attrs, :kSecUseDataProtectionKeychain)  # applied via _apply_keychain_target!, not pairs
        @test !haskey(attrs, :kSecUseKeychain)
    end

    @testset "pairs protocol — LoginKeychain (explicit)" begin
        item  = GenericPasswordItem(service="svc", account="acct", keychain=LoginKeychain())
        attrs = Dict(pairs(item))
        @test attrs[:kSecClass] == :kSecClassGenericPassword
        @test !haskey(attrs, :kSecUseDataProtectionKeychain)
        @test !haskey(attrs, :kSecUseKeychain)
    end

    @testset "keychain_target dispatch" begin
        @test keychain_target(GenericPasswordItem(service="svc")) isa LoginKeychain
        @test keychain_target(GenericPasswordItem(service="svc", keychain=DataProtectionKeychain())) isa DataProtectionKeychain
        @test keychain_target(GenericPasswordItem(service="svc", keychain=FileKeychain("/tmp/x"))) isa FileKeychain
    end

    @testset "pairs protocol — access_control takes precedence over accessible" begin
        ctrl = AccessControlItem(:kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                 AccessControlFlags.BiometryAny)
        item  = GenericPasswordItem(service="svc", account="acct",
                                    accessible=:kSecAttrAccessibleWhenUnlocked,
                                    access_control=ctrl)
        attrs = Dict(pairs(item))
        @test haskey(attrs, :kSecAttrAccessControl)
        @test !haskey(attrs, :kSecAttrAccessible)
    end

    @testset "AccessControlFlags values" begin
        @test AccessControlFlags.UserPresence        == UInt64(1 << 0)
        @test AccessControlFlags.BiometryAny         == UInt64(1 << 1)
        @test AccessControlFlags.BiometryCurrentSet  == UInt64(1 << 3)
        @test AccessControlFlags.DevicePasscode      == UInt64(1 << 4)
        @test AccessControlFlags.Companion           == UInt64(1 << 5)
        @test AccessControlFlags.Or                  == UInt64(1 << 14)
        @test AccessControlFlags.And                 == UInt64(1 << 15)
        @test AccessControlFlags.PrivateKeyUsage     == UInt64(1 << 30)
        @test AccessControlFlags.ApplicationPassword == UInt64(1 << 31)
    end

    # ── Integration tests ──────────────────────────────────────────────────────

    @static if Sys.isapple()

        has_dp = data_protection_available()

        @testset "Login keychain — basic CRUD" begin
            service = "KeychainServices.jl.tests.$(getpid())"
            account = "integration-user"
            item    = GenericPasswordItem(service=service, account=account)

            try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

            secret  = secret_buf("integration-secret")
            rotated = secret_buf("integration-secret-rotated")

            add_item!(item, secret)

            s = copy_secret(item)
            seekstart(secret)
            @test s == secret
            Base.shred!(s)

            # copy_secret with explicit `into` IO
            buf = Base.SecretBuffer()
            copy_secret(item; into=buf)
            seekstart(buf); seekstart(secret)
            @test buf == secret
            Base.shred!(buf)

            results = search_items(item)
            @test length(results) == 1
            r = results[1]
            @test r.service    == service
            @test r.account    == account
            @test r.created_at === nothing || r.created_at isa DateTime
            @test r.updated_at === nothing || r.updated_at isa DateTime

            # update_item! without secret rotation (attributes only)
            update_item!(item, GenericPasswordItem(label="Updated label"))
            results2 = search_items(item)
            @test results2[1].label == "Updated label"

            update_item!(item, GenericPasswordItem(label="Rotated label"); secret=rotated)

            s3 = copy_secret(item)
            seekstart(rotated)
            @test s3 == rotated
            Base.shred!(s3)

            results3 = search_items(item)
            @test results3[1].label == "Rotated label"

            delete_item!(item)
            @test_throws KeychainItemNotFoundError copy_secret(item)
            @test search_items(item) == GenericPasswordItem[]

            Base.shred!(secret); Base.shred!(rotated)
        end

        @testset "Login keychain — String and Vector{UInt8} secret inputs" begin
            service = "KeychainServices.jl.secret-types.$(getpid())"
            item    = GenericPasswordItem(service=service, account="user")

            # String secret
            try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end
            add_item!(item, "string-secret")
            s = copy_secret(item)
            @test read(s) == Vector{UInt8}("string-secret")
            Base.shred!(s)
            delete_item!(item)

            # Vector{UInt8} secret
            raw = Vector{UInt8}("bytes-secret")
            add_item!(item, raw)
            s = copy_secret(item)
            @test read(s) == raw
            Base.shred!(s)
            delete_item!(item)
        end

        @testset "Login keychain — tri-state synchronizable" begin
            service = "KeychainServices.jl.synchronizable.$(getpid())"
            item    = GenericPasswordItem(service=service, account="user", synchronizable=false)

            try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

            secret = secret_buf("sync-secret")
            add_item!(item, secret)

            s = copy_secret(item)
            seekstart(secret)
            @test s == secret
            Base.shred!(s)

            results = search_items(item)
            @test results[1].synchronizable == false

            delete_item!(item)
            Base.shred!(secret)
        end

        @testset "Login keychain — extended attributes" begin
            service = "KeychainServices.jl.attrs.$(getpid())"
            item    = GenericPasswordItem(
                service     = service,
                account     = "user",
                label       = "Initial Label",
                description = "Integration description",
                comment     = "Integration comment",
                is_invisible= false,
                is_negative = false,
                generic_data= collect(codeunits("metadata")),
            )

            try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

            secret = secret_buf("attr-secret")
            add_item!(item, secret)

            s = copy_secret(item)
            seekstart(secret)
            @test s == secret
            Base.shred!(s)

            results = search_items(item)
            r = results[1]
            @test r.service     == service
            @test r.label       == "Initial Label"
            @test r.description === nothing || r.description == "Integration description"
            @test r.comment     === nothing || r.comment     == "Integration comment"
            @test r.is_invisible === nothing || r.is_invisible == false
            @test r.is_negative  === nothing || r.is_negative  == false
            @test r.generic_data === nothing || r.generic_data == collect(codeunits("metadata"))

            delete_item!(item)
            Base.shred!(secret)
        end

        @testset "Data Protection keychain — basic CRUD" begin
            service = "KeychainServices.jl.dp.tests.$(getpid())"
            item    = GenericPasswordItem(service=service, account="user",
                                          keychain=DataProtectionKeychain())
            if has_dp
                try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

                secret  = secret_buf("dp-secret")
                rotated = secret_buf("dp-secret-rotated")

                add_item!(item, secret)

                s = copy_secret(item)
                seekstart(secret)
                @test s == secret
                Base.shred!(s)

                results = search_items(item)
                @test results[1].service == service

                update_item!(item, GenericPasswordItem(label="DP label"); secret=rotated)

                s2 = copy_secret(item)
                seekstart(rotated)
                @test s2 == rotated
                Base.shred!(s2)

                results2 = search_items(item)
                @test results2[1].label == "DP label"

                delete_item!(item)
                Base.shred!(secret); Base.shred!(rotated)
            else
                @test_throws KeychainPermissionError add_item!(item, secret_buf("x"))
            end
        end

        @testset "Data Protection keychain — extended attributes" begin
            service = "KeychainServices.jl.dp.attrs.$(getpid())"
            item    = GenericPasswordItem(
                service     = service,
                account     = "user",
                label       = "Initial Label",
                accessible  = :kSecAttrAccessibleWhenUnlocked,
                generic_data= collect(codeunits("metadata")),
                keychain    = DataProtectionKeychain(),
            )

            if has_dp
                try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

                secret = secret_buf("dp-attr-secret")
                add_item!(item, secret)

                s = copy_secret(item)
                seekstart(secret)
                @test s == secret
                Base.shred!(s)

                results = search_items(item)
                r = results[1]
                @test r.label        == "Initial Label"
                @test r.accessible   == :kSecAttrAccessibleWhenUnlocked
                @test r.generic_data === nothing || r.generic_data == collect(codeunits("metadata"))

                delete_item!(item)
                Base.shred!(secret)
            else
                @test_throws KeychainPermissionError add_item!(item, secret_buf("x"))
            end
        end

        @testset "Synchronizable rejects ThisDeviceOnly accessibility" begin
            item = GenericPasswordItem(
                service        = "KeychainServices.jl.validation.$(getpid())",
                account        = "user",
                synchronizable = true,
                accessible     = :kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            )
            @test_throws KeychainOperationError add_item!(item, secret_buf("invalid"))
            @test_throws KeychainOperationError search_items(item)
        end

        @testset "File keychain — basic CRUD" begin
            mktempdir() do dir
                kc_path = joinpath(dir, "test.keychain-db")
                run(`security create-keychain -p test-kc-pass $kc_path`)
                try
                    service = "KeychainServices.jl.filekc.$(getpid())"
                    item    = GenericPasswordItem(service=service, account="user",
                                                  keychain=FileKeychain(kc_path))

                    secret  = secret_buf("file-kc-secret")
                    rotated = secret_buf("file-kc-secret-rotated")

                    add_item!(item, secret)

                    s = copy_secret(item)
                    seekstart(secret)
                    @test s == secret
                    Base.shred!(s)

                    results = search_items(item)
                    @test results[1].service == service

                    update_item!(item, GenericPasswordItem(label="File KC label"); secret=rotated)

                    s2 = copy_secret(item)
                    seekstart(rotated)
                    @test s2 == rotated
                    Base.shred!(s2)

                    results2 = search_items(item)
                    @test results2[1].label == "File KC label"

                    delete_item!(item)
                    @test_throws KeychainItemNotFoundError copy_secret(item)

                    Base.shred!(secret); Base.shred!(rotated)
                finally
                    run(`security delete-keychain $kc_path`)
                end
            end
        end

    end # @static if Sys.isapple()

end # @testset "KeychainServices.jl"
