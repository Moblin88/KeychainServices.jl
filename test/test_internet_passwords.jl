@testset "InternetPasswordItem defaults" begin
    item = InternetPasswordItem(server="api.example.com", account="alice")
    @test item.server              == "api.example.com"
    @test item.account             == "alice"
    @test item.path                === nothing
    @test item.port                === nothing
    @test item.protocol            === nothing
    @test item.authentication_type === nothing
    @test item.security_domain     === nothing
    @test item.label               === nothing
    @test item.keychain            isa LoginKeychain
    @test item.created_at          === nothing
    @test item.updated_at          === nothing
end

@testset "InternetPasswordItem — pairs protocol — LoginKeychain" begin
    item  = InternetPasswordItem(
        server   = "api.example.com",
        account  = "alice",
        protocol = :kSecAttrProtocolHTTPS,
        port     = 443,
        path     = "/v1",
        label    = "Example API",
    )
    attrs = Dict(pairs(item))
    @test attrs[:kSecClass]            == :kSecClassInternetPassword
    @test attrs[:kSecAttrServer]       == "api.example.com"
    @test attrs[:kSecAttrAccount]      == "alice"
    @test attrs[:kSecAttrProtocol]     == :kSecAttrProtocolHTTPS
    @test attrs[:kSecAttrPort]         == 443
    @test attrs[:kSecAttrPath]         == "/v1"
    @test attrs[:kSecAttrLabel]        == "Example API"
    @test !haskey(attrs, :kSecUseDataProtectionKeychain)
    @test !haskey(attrs, :kSecUseKeychain)
end

@testset "InternetPasswordItem — pairs protocol — DataProtectionKeychain" begin
    item  = InternetPasswordItem(server="s", account="a", keychain=DataProtectionKeychain())
    attrs = Dict(pairs(item))
    @test attrs[:kSecClass] == :kSecClassInternetPassword
    @test !haskey(attrs, :kSecUseDataProtectionKeychain)
end

@testset "InternetPasswordItem — pairs protocol — timestamps not included" begin
    item  = InternetPasswordItem(server="s", account="a",
                                 created_at=DateTime(2024,1,1), updated_at=DateTime(2024,1,2))
    attrs = Dict(pairs(item))
    @test !haskey(attrs, :kSecAttrCreationDate)
    @test !haskey(attrs, :kSecAttrModificationDate)
end

@testset "InternetPasswordItem — synchronizable + ThisDeviceOnly validation" begin
    bad = InternetPasswordItem(
        server         = "s",
        account        = "a",
        synchronizable = true,
        accessible     = :kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    )
    @test_throws KeychainOperationError pairs(bad)
end

@testset "InternetPasswordItem — unsupported accessible value" begin
    bad = InternetPasswordItem(server="s", account="a", accessible=:kSecAttrBogus)
    @test_throws KeychainOperationError pairs(bad)
end

@testset "InternetPasswordItem — pairs protocol — access_control takes precedence over accessible" begin
    ctrl  = AccessControlItem(:kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                               AccessControlFlags.BiometryAny)
    item  = InternetPasswordItem(server="s", account="a",
                                 accessible=:kSecAttrAccessibleWhenUnlocked,
                                 access_control=ctrl)
    attrs = Dict(pairs(item))
    @test  haskey(attrs, :kSecAttrAccessControl)
    @test !haskey(attrs, :kSecAttrAccessible)
end

@testset "InternetPasswordItem — keychain_target dispatch" begin
    @test keychain_target(InternetPasswordItem(server="s")) isa LoginKeychain
    @test keychain_target(InternetPasswordItem(server="s", keychain=DataProtectionKeychain())) isa DataProtectionKeychain
    @test keychain_target(InternetPasswordItem(server="s", keychain=FileKeychain("/tmp/x"))) isa FileKeychain
end

@static if Sys.isapple()

    @testset "Internet password — basic CRUD" begin
        server  = "KeychainServices.jl.tests.$(getpid()).example.com"
        account = "integration-user"
        item    = InternetPasswordItem(server=server, account=account)

        try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

        Base.shred!(Base.SecretBuffer("inet-secret")) do secret
        Base.shred!(Base.SecretBuffer("inet-secret-rotated")) do rotated
            add_item!(item, secret)

            Base.shred!(copy_secret(item)) do s
                seekstart(secret)
                @test s == secret
            end

            results = search_items(item)
            @test length(results) == 1
            r = results[1]
            @test r.server     == server
            @test r.account    == account
            @test r.created_at === nothing || r.created_at isa DateTime
            @test r.updated_at === nothing || r.updated_at isa DateTime

            update_item!(item, InternetPasswordItem(label="Updated label"))
            results2 = search_items(item)
            @test results2[1].label == "Updated label"

            update_item!(item, InternetPasswordItem(label="Rotated label"), rotated)

            Base.shred!(copy_secret(item)) do s3
                seekstart(rotated)
                @test s3 == rotated
            end

            results3 = search_items(item)
            @test results3[1].label == "Rotated label"

            delete_item!(item)
            @test_throws KeychainItemNotFoundError copy_secret(item)
            @test search_items(item) == InternetPasswordItem[]
        end # rotated
        end # secret
    end

    @testset "Internet password — extended attributes" begin
        server = "KeychainServices.jl.inet.attrs.$(getpid()).example.com"
        item   = InternetPasswordItem(
            server              = server,
            account             = "user",
            protocol            = :kSecAttrProtocolHTTPS,
            port                = 443,
            path                = "/api/v1",
            authentication_type = :kSecAttrAuthenticationTypeHTTPBasic,
            label               = "HTTPS Basic",
            description         = "Integration internet password",
            comment             = "Integration comment",
        )

        try delete_item!(item) catch e; @test e isa KeychainItemNotFoundError end

        Base.shred!(Base.SecretBuffer("inet-attr-secret")) do secret
            add_item!(item, secret)

            Base.shred!(copy_secret(item)) do s
                seekstart(secret)
                @test s == secret
            end

            results = search_items(item)
            r = results[1]
            @test r.server              == server
            @test r.account             == "user"
            @test r.port                === nothing || r.port                == 443
            @test r.path                === nothing || r.path                == "/api/v1"
            @test r.protocol            === nothing || r.protocol            == :kSecAttrProtocolHTTPS
            @test r.authentication_type === nothing || r.authentication_type == :kSecAttrAuthenticationTypeHTTPBasic
            @test r.label               === nothing || r.label               == "HTTPS Basic"
            @test r.description         === nothing || r.description         == "Integration internet password"
            @test r.comment             === nothing || r.comment             == "Integration comment"

            delete_item!(item)
        end
    end

end # @static if Sys.isapple()
