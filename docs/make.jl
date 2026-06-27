using Documenter
using KeychainServices

makedocs(
    sitename = "KeychainServices.jl",
    modules  = [KeychainServices],
    format   = Documenter.HTML(
        canonical = "https://Moblin88.github.io/KeychainServices.jl/",
        prettyurls = get(ENV, "CI", nothing) == "true",
    ),
    pages = [
        "Home"                             => "index.md",
        "Keychain Types & Entitlements"    => "keychain-types.md",
        "API Reference"                    => "api.md",
    ],
    warnonly = [:missing_docs],
)

deploydocs(
    repo       = "github.com/Moblin88/KeychainServices.jl",
    devbranch  = "main",
    push_preview = true,
)
