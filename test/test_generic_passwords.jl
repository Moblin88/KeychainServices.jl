@testset "GenericPasswordItem defaults" begin
    item = GenericPasswordItem(service="svc", account="acct")
    @test item.service    == "svc"
    @test item.account    == "acct"
    @test item.label      === nothing
    @test item.keychain   isa LoginKeychain
    @test item.created_at === nothing
    @test item.updated_at === nothing
end

@testset "Secret inputs — accepted types" begin
    item = GenericPasswordItem(service="svc", account="acct")
    @test_throws MethodError add_item!(item, 42)
    @test_throws MethodError add_item!(item, :symbol)
end

@testset "GenericPasswordItem — synchronizable + ThisDeviceOnly validation" begin
    bad = GenericPasswordItem(
        service="svc", account="acct",
        synchronizable=true,
        accessible=:kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    )
    @test_throws KeychainOperationError pairs(bad)
end

@testset "GenericPasswordItem — unsupported accessible value" begin
    bad = GenericPasswordItem(service="svc", account="acct", accessible=:kSecAttrBogus)
    @test_throws KeychainOperationError pairs(bad)
end

@testset "GenericPasswordItem — pairs protocol — LoginKeychain (default)" begin
    item  = GenericPasswordItem(service="svc", account="acct", label="lbl")
    attrs = Dict(pairs(item))
    @test attrs[:kSecClass]       == :kSecClassGenericPassword
    @test attrs[:kSecAttrService] == "svc"
    @test attrs[:kSecAttrAccount] == "acct"
    @test attrs[:kSecAttrLabel]   == "lbl"
    @test !haskey(attrs, :kSecUseDataProtectionKeychain)
    @test !haskey(attrs, :kSecUseKeychain)
end

@testset "GenericPasswordItem — pairs protocol — LoginKeychain (explicit)" begin
    item  = GenericPasswordItem(service="svc", account="acct", keychain=LoginKeychain())
    attrs = Dict(pairs(item))
    @test attrs[:kSecClass] == :kSecClassGenericPassword
    @test !haskey(attrs, :kSecUseDataProtectionKeychain)
    @test !haskey(attrs, :kSecUseKeychain)
end

@testset "GenericPasswordItem — pairs protocol — DataProtectionKeychain" begin
    item  = GenericPasswordItem(service="svc", account="acct", keychain=DataProtectionKeychain())
    attrs = Dict(pairs(item))
    @test attrs[:kSecClass] == :kSecClassGenericPassword
    @test !haskey(attrs, :kSecUseDataProtectionKeychain)  # applied via _apply_keychain_target!, not pairs
    @test !haskey(attrs, :kSecUseKeychain)
end

@testset "GenericPasswordItem — pairs protocol — timestamps not included" begin
    item  = GenericPasswordItem(service="svc", account="acct",
                                created_at=DateTime(2024,1,1), updated_at=DateTime(2024,1,2))
    attrs = Dict(pairs(item))
    @test !haskey(attrs, :kSecAttrCreationDate)
    @test !haskey(attrs, :kSecAttrModificationDate)
end

@testset "GenericPasswordItem — pairs protocol — access_control takes precedence over accessible" begin
    ctrl = AccessControlItem(:kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                             AccessControlFlags.BiometryAny)
    item  = GenericPasswordItem(service="svc", account="acct",
                                accessible=:kSecAttrAccessibleWhenUnlocked,
                                access_control=ctrl)
    attrs = Dict(pairs(item))
    @test  haskey(attrs, :kSecAttrAccessControl)
    @test !haskey(attrs, :kSecAttrAccessible)
end

@testset "GenericPasswordItem — keychain_target dispatch" begin
    @test keychain_target(GenericPasswordItem(service="svc")) isa LoginKeychain
    @test keychain_target(GenericPasswordItem(service="svc", keychain=DataProtectionKeychain())) isa DataProtectionKeychain
    @test keychain_target(GenericPasswordItem(service="svc", keychain=FileKeychain("/tmp/x"))) isa FileKeychain
end

@static if Sys.isapple()

    has_dp = probe_data_protection_entitlement()

    @testset "Login keychain — basic CRUD" begin
        service = "KeychainServices.jl.tests.$(getpid())"
        account = "integration-user"
        item    = GenericPasswordItem(service=service, account=account)

        try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

        Base.shred!(Base.SecretBuffer("integration-secret")) do secret
        Base.shred!(Base.SecretBuffer("integration-secret-rotated")) do rotated
            add_item!(item, secret)

            Base.shred!(copy_secret(item)) do s
                seekstart(secret)
                @test s == secret
            end

            # copy_secret with explicit `into` IO
            Base.shred!(Base.SecretBuffer()) do buf
                copy_secret(item; into=buf)
                seekstart(buf); seekstart(secret)
                @test buf == secret
            end

            results = search_items(item)
            @test length(results) == 1
            r = results[1]
            @test r.service    == service
            @test r.account    == account
            @test r.created_at === nothing || r.created_at isa DateTime
            @test r.updated_at === nothing || r.updated_at isa DateTime

            update_item!(item, GenericPasswordItem(label="Updated label"))
            results2 = search_items(item)
            @test results2[1].label == "Updated label"

            update_item!(item, GenericPasswordItem(label="Rotated label"), rotated)

            Base.shred!(copy_secret(item)) do s3
                seekstart(rotated)
                @test s3 == rotated
            end

            results3 = search_items(item)
            @test results3[1].label == "Rotated label"

            delete_item!(item)
            @test_throws KeychainItemNotFoundError copy_secret(item)
            @test search_items(item) == GenericPasswordItem[]
        end # rotated
        end # secret
    end

    @testset "Login keychain — String and Vector{UInt8} secret inputs" begin
        service = "KeychainServices.jl.secret-types.$(getpid())"
        item    = GenericPasswordItem(service=service, account="user")

        try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end
        add_item!(item, "string-secret")
        Base.shred!(copy_secret(item)) do s
            @test read(s) == Vector{UInt8}("string-secret")
        end
        delete_item!(item)

        raw = Vector{UInt8}("bytes-secret")
        add_item!(item, raw)
        Base.shred!(copy_secret(item)) do s
            @test read(s) == raw
        end
        delete_item!(item)
    end

    @testset "Login keychain — tri-state synchronizable" begin
        service = "KeychainServices.jl.synchronizable.$(getpid())"
        item    = GenericPasswordItem(service=service, account="user", synchronizable=false)

        try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

        Base.shred!(Base.SecretBuffer("sync-secret")) do secret
            add_item!(item, secret)

            Base.shred!(copy_secret(item)) do s
                seekstart(secret)
                @test s == secret
            end

            results = search_items(item)
            @test results[1].synchronizable == false

            delete_item!(item)
        end
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

        Base.shred!(Base.SecretBuffer("attr-secret")) do secret
            add_item!(item, secret)

            Base.shred!(copy_secret(item)) do s
                seekstart(secret)
                @test s == secret
            end

            results = search_items(item)
            r = results[1]
            @test r.service      == service
            @test r.label        == "Initial Label"
            @test r.description  === nothing || r.description  == "Integration description"
            @test r.comment      === nothing || r.comment      == "Integration comment"
            @test r.is_invisible === nothing || r.is_invisible == false
            @test r.is_negative  === nothing || r.is_negative  == false
            @test r.generic_data === nothing || r.generic_data == collect(codeunits("metadata"))

            delete_item!(item)
        end
    end

    @testset "Data Protection keychain — basic CRUD" begin
        service = "KeychainServices.jl.dp.tests.$(getpid())"
        item    = GenericPasswordItem(service=service, account="user",
                                      keychain=DataProtectionKeychain())
        if has_dp
            try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

            Base.shred!(Base.SecretBuffer("dp-secret")) do secret
            Base.shred!(Base.SecretBuffer("dp-secret-rotated")) do rotated
                add_item!(item, secret)

                Base.shred!(copy_secret(item)) do s
                    seekstart(secret)
                    @test s == secret
                end

                results = search_items(item)
                @test results[1].service == service

                update_item!(item, GenericPasswordItem(label="DP label"), rotated)

                Base.shred!(copy_secret(item)) do s2
                    seekstart(rotated)
                    @test s2 == rotated
                end

                results2 = search_items(item)
                @test results2[1].label == "DP label"

                delete_item!(item)
            end # rotated
            end # secret
        else
            @test_throws KeychainPermissionError add_item!(item, "x")
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

            Base.shred!(Base.SecretBuffer("dp-attr-secret")) do secret
                add_item!(item, secret)

                Base.shred!(copy_secret(item)) do s
                    seekstart(secret)
                    @test s == secret
                end

                results = search_items(item)
                r = results[1]
                @test r.label        == "Initial Label"
                @test r.accessible   == :kSecAttrAccessibleWhenUnlocked
                @test r.generic_data === nothing || r.generic_data == collect(codeunits("metadata"))

                delete_item!(item)
            end
        else
            @test_throws KeychainPermissionError add_item!(item, "x")
        end
    end

    @testset "Synchronizable rejects ThisDeviceOnly accessibility" begin
        item = GenericPasswordItem(
            service        = "KeychainServices.jl.validation.$(getpid())",
            account        = "user",
            synchronizable = true,
            accessible     = :kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        )
        @test_throws KeychainOperationError add_item!(item, "invalid")
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

                Base.shred!(Base.SecretBuffer("file-kc-secret")) do secret
                Base.shred!(Base.SecretBuffer("file-kc-secret-rotated")) do rotated
                    add_item!(item, secret)

                    Base.shred!(copy_secret(item)) do s
                        seekstart(secret)
                        @test s == secret
                    end

                    results = search_items(item)
                    @test results[1].service == service

                    update_item!(item, GenericPasswordItem(label="File KC label"), rotated)

                    Base.shred!(copy_secret(item)) do s2
                        seekstart(rotated)
                        @test s2 == rotated
                    end

                    results2 = search_items(item)
                    @test results2[1].label == "File KC label"

                    delete_item!(item)
                    @test_throws KeychainItemNotFoundError copy_secret(item)
                end # rotated
                end # secret
            finally
                run(`security delete-keychain $kc_path`)
            end
        end
    end

end # @static if Sys.isapple()
