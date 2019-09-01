sudo docker container stop proxycontainer
sudo docker container rm proxycontainer
dir=$(pwd)
dir+=/src
echo $dir
sudo docker build -t ubuntu:proxy .
sudo docker create --volume /$dir:/src -it  --name proxycontainer ubuntu:proxy