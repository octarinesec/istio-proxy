if [ "$1" == "" ]; then
    echo "Usage: $0 <istio-version>"
    exit
fi

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
istio_version=$1

echo "Building Octarine Istio Proxy with version: $istio_version"

echo "Removing previous envoy binary"
rm -f $script_dir/envoy
if [ $? -ne 0 ]; then
    echo "Couldnt remove envoy."
    exit $?
fi

echo "Copying envoy binary..."
cp $script_dir/../bazel-bin/src/envoy/envoy $script_dir/envoy
if [ $? -ne 0 ]; then
    echo "Couldnt find envoy."
    exit $?
fi

echo "Building envoy docker file"
docker build $script_dir --tag octarinesec/istio-proxy:$istio_version --build-arg istio_version=$istio_version --build-arg envoy_bin=$script_dir/envoy
if [ $? -ne 0 ]; then
    echo "Couldnt build docker file."
    exit $?
fi
echo "Done."

echo "Login to docker"
docker login -u $DOCKER_USERNAME -p $DOCKER_PASSWORD
if [ $? -ne 0 ]; then
    echo "Couldnt login to docker."
    exit $?
fi
echo "Done."

echo "Pushing octarine istio-proxy image"
docker push octarinesec/istio-proxy:$istio_version
if [ $? -ne 0 ]; then
    echo "Couldnt push image."
    exit $?
fi
echo "Done."
