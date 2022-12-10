load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "prometheus",
    srcs = [
        "prometheus.go",
        "prometheus_verify.go",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/metric:metric_go_proto"],
)

go_test(
    name = "prometheus_test",
    size = "small",
    srcs = ["prometheus_test.go"],
    library = ":prometheus",
    deps = [
        "//pkg/metric:metric_go_proto",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)
