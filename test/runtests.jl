using KeychainServices
using Dates
using Test

# ── Helpers ────────────────────────────────────────────────────────────────────

secret_buf(s::String) = Base.SecretBuffer(s)

# Use the Security C API directly to probe whether the current process holds the
# entitlements required for Data Protection keychain access.
# `SecItemCopyMatching` with `kSecUseDataProtectionKeychain=true` returns
# `errSecMissingEntitlement` (-34018) when the entitlement is absent; an
# `errSecItemNotFound` response confirms that the query reached the keychain
# subsystem successfully.
data_protection_available() = @static Sys.isapple() ? probe_data_protection_entitlement() : false

# ── Platform / type tests (no entitlement required) ───────────────────────────

@testset "KeychainServices.jl" begin

    @testset "Platform support" begin
        if Sys.isapple()
            @test add_item!    isa Function
            @test copy_matching isa Function
            @test update_item! isa Function
            @test delete_item! isa Function
        else
            item = GenericPasswordItem(service="svc", account="acct")
            @test_throws UnsupportedPlatformError add_item!(item, secret_buf("x"))
            @test_throws UnsupportedPlatformError copy_matching(item)
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
        @test item.service  == "svc"
        @test item.account  == "acct"
        @test item.label    === nothing
        @test item.keychain isa LoginKeychain
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

    @testset "pairs protocol — LoginKeychain (default)" begin
        item  = GenericPasswordItem(service="svc", account="acct", label="lbl")
        attrs = Dict(pairs(item))
        @test attrs[:kSecClass]    == :kSecClassGenericPassword
        @test attrs[:kSecAttrService] == "svc"
        @test attrs[:kSecAttrAccount] == "acct"
        @test attrs[:kSecAttrLabel]   == "lbl"
        @test !haskey(attrs, :kSecUseDataProtectionKeychain)
        @test !haskey(attrs, :kSecUseKeychain)
    end

    @testset "pairs protocol — DataProtectionKeychain" begin
        item  = GenericPasswordItem(service="svc", account="acct", keychain=DataProtectionKeychain())
        attrs = Dict(pairs(item))
        @test attrs[:kSecClass]                     == :kSecClassGenericPassword
        @test attrs[:kSecUseDataProtectionKeychain] === true
        @test !haskey(attrs, :kSecUseKeychain)
    end

    @testset "pairs protocol — LoginKeychain (explicit)" begin
        item  = GenericPasswordItem(service="svc", account="acct", keychain=LoginKeychain())
        attrs = Dict(pairs(item))
        @test attrs[:kSecClass] == :kSecClassGenericPassword
        @test !haskey(attrs, :kSecUseDataProtectionKeychain)
        @test !haskey(attrs, :kSecUseKeychain)
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

        # Basic CRUD runs against the login keychain (default), so no entitlement needed.
        @testset "Login keychain — basic CRUD" begin
            service = "KeychainServices.jl.tests.$(getpid())"
            account = "integration-user"
            item    = GenericPasswordItem(service=service, account=account)

            try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

            secret  = secret_buf("integration-secret")
            rotated = secret_buf("integration-secret-rotated")

            add_item!(item, secret)

            r1 = copy_matching(item; return_data=true)
            seekstart(secret)
            @test r1.secret == secret

            r2 = copy_matching(item; return_attributes=true)
            @test r2.item.service == service
            @test r2.item.account == account
            @test r2.created_at === nothing || r2.created_at isa DateTime
            @test r2.updated_at === nothing || r2.updated_at isa DateTime

            update_item!(item, GenericPasswordItem(label="Updated label"); secret=rotated)
            r3 = copy_matching(item; return_data=true, return_attributes=true)
            seekstart(rotated)
            @test r3.secret      == rotated
            @test r3.item.label  == "Updated label"

            delete_item!(item)
            @test_throws KeychainItemNotFoundError copy_matching(item; return_data=true)

            Base.shred!(secret); Base.shred!(rotated)
            r1.secret !== nothing && Base.shred!(r1.secret)
            r3.secret !== nothing && Base.shred!(r3.secret)
        end

        @testset "Login keychain — tri-state synchronizable" begin
            service = "KeychainServices.jl.synchronizable.$(getpid())"
            item    = GenericPasswordItem(service=service, account="user", synchronizable=false)

            try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

            secret = secret_buf("sync-secret")
            add_item!(item, secret)
            r = copy_matching(item; return_data=true, return_attributes=true)
            seekstart(secret)
            @test r.secret == secret
            @test r.item.synchronizable == false

            delete_item!(item)
            Base.shred!(secret)
            r.secret !== nothing && Base.shred!(r.secret)
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
            r = copy_matching(item; return_data=true, return_attributes=true)
            seekstart(secret)
            @test r.secret          == secret
            @test r.item.service    == service
            @test r.item.label      == "Initial Label"
            @test r.item.description === nothing || r.item.description == "Integration description"
            @test r.item.comment     === nothing || r.item.comment     == "Integration comment"
            @test r.item.is_invisible === nothing || r.item.is_invisible == false
            @test r.item.is_negative  === nothing || r.item.is_negative  == false
            @test r.item.generic_data === nothing || r.item.generic_data == collect(codeunits("metadata"))

            delete_item!(item)
            Base.shred!(secret)
            r.secret !== nothing && Base.shred!(r.secret)
        end

        # Data Protection keychain tests require the keychain-access-groups entitlement.
        @testset "Data Protection keychain — basic CRUD" begin
            service = "KeychainServices.jl.dp.tests.$(getpid())"
            item    = GenericPasswordItem(service=service, account="user",
                                          keychain=DataProtectionKeychain())
            if has_dp
                try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

                secret  = secret_buf("dp-secret")
                rotated = secret_buf("dp-secret-rotated")

                add_item!(item, secret)
                r = copy_matching(item; return_data=true, return_attributes=true)
                seekstart(secret)
                @test r.secret == secret
                @test r.item.service == service

                update_item!(item, GenericPasswordItem(label="DP label"); secret=rotated)
                r2 = copy_matching(item; return_data=true, return_attributes=true)
                seekstart(rotated)
                @test r2.secret     == rotated
                @test r2.item.label == "DP label"

                delete_item!(item)
                Base.shred!(secret); Base.shred!(rotated)
                r.secret  !== nothing && Base.shred!(r.secret)
                r2.secret !== nothing && Base.shred!(r2.secret)
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
                r = copy_matching(item; return_data=true, return_attributes=true)

                @test r.secret         == secret
                @test r.item.label     == "Initial Label"
                @test r.item.accessible == :kSecAttrAccessibleWhenUnlocked
                @test r.item.generic_data === nothing || r.item.generic_data == collect(codeunits("metadata"))

                delete_item!(item)
                Base.shred!(secret)
                r.secret !== nothing && Base.shred!(r.secret)
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
            @test_throws KeychainOperationError copy_matching(item; return_attributes=true)
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

                    r1 = copy_matching(item; return_data=true, return_attributes=true)
                    seekstart(secret)
                    @test r1.secret == secret
                    @test r1.item.service == service

                    update_item!(item, GenericPasswordItem(label="File KC label"); secret=rotated)
                    r2 = copy_matching(item; return_data=true, return_attributes=true)
                    seekstart(rotated)
                    @test r2.secret     == rotated
                    @test r2.item.label == "File KC label"

                    delete_item!(item)
                    @test_throws KeychainItemNotFoundError copy_matching(item; return_data=true)

                    Base.shred!(secret); Base.shred!(rotated)
                    r1.secret !== nothing && Base.shred!(r1.secret)
                    r2.secret !== nothing && Base.shred!(r2.secret)
                finally
                    # deregister from securityd before the temp dir is removed
                    run(`security delete-keychain $kc_path`)
                end
            end
        end

    end # @static if Sys.isapple()

end # @testset "KeychainServices.jl"
