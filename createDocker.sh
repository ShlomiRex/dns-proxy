sudo docker container stop proxycontainer
sudo docker container rm proxycontainer
dir=$(pwd)
dir+=/src
echo $dir
sudo docker build -t ubuntu:proxybase .
sudo docker create --volume /$dir:/src -it  --name proxycontainer ubuntu:proxybase