using KeychainServices
using Dates
using Test

@testset "KeychainServices.jl" begin
    include("test_platform.jl")
    include("test_access_control.jl")
    include("test_generic_passwords.jl")
    include("test_internet_passwords.jl")
end
