ARG istio_version
ARG envoy_bin

FROM docker.io/istio/proxyv2:${istio_version}
ADD ${envoy_bin} /usr/local/bin
