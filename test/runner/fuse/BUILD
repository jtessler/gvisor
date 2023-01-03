package(licenses = ["notice"])

go_binary(
    name = "fuse",
    srcs = ["fuse.go"],
    visibility = ["//test/runner:__subpackages__"],
    deps = [
        "//pkg/log",
        "@com_github_hanwen_go_fuse//fs:go_default_library",
        "@com_github_hanwen_go_fuse//fuse:go_default_library",
    ],
)
