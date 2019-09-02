sudo docker stop proxycontainer 
#sudo docker start -i proxycontainer 
dir=$(pwd)
dir+=/src
sudo docker run --volume /$dir:/src -it ubuntu:proxybase