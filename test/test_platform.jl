@testset "Platform support" begin
    if Sys.isapple()
        @test add_item!    isa Function
        @test search_items isa Function
        @test copy_secret  isa Function
        @test update_item! isa Function
        @test delete_item! isa Function
    else
        item = GenericPasswordItem(service="svc", account="acct")
        @test_throws UnsupportedPlatformError add_item!(item, "x")
        @test_throws UnsupportedPlatformError search_items(item)
        @test_throws UnsupportedPlatformError copy_secret(item)
        @test_throws UnsupportedPlatformError delete_item!(item)
    end
end

@testset "Type API" begin
    @test GenericPasswordItem    <: AbstractKeychainItem
    @test InternetPasswordItem   <: AbstractKeychainItem
    @test DataProtectionKeychain <: KeychainTarget
    @test LoginKeychain          <: KeychainTarget
    @test FileKeychain           <: KeychainTarget
    @test AccessControlItem      isa DataType
end
