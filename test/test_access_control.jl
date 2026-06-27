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

@testset "AccessControlItem — unsupported accessible value" begin
    ctrl = AccessControlItem(:kSecAttrBogus, AccessControlFlags.BiometryAny)
    item = GenericPasswordItem(service="svc", account="acct", access_control=ctrl)
    @test_throws KeychainOperationError pairs(item)
end
