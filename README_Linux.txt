#!/bin/sh
# INSTALLING ON Ubuntu/Kbuntu/Debian LINUX
#

if [ -r /usr/bin/apt-get ] ; 
then

  echo you are running on a system with apt-get.

  # Edit /etc/apt/sources.list and uncomment the lines with "universe"
  apt-get update

  # General build tools:
  apt-get -y install make gcc g++ 

  # Libraries required for AFFLIB:
  apt-get -y install zlib1g-dev libssl-dev libncurses5-dev 
  apt-get -y install libcurl4-openssl-dev libexpat1-dev libreadline5-dev

  # Libraries if you want to make a release:
  apt-get -y install automake1.9  autoconf libtool
  exit 0
fi

if [ -r /usr/bin/yum ] ; 
then
  #================================================================
  #INSTALLOING ON FEDORA CORE 6:
  #
  # When you build Linux, tell it that you want developer tools.
  #
  yum upgrade all
  yum install libssl-dev libncurses5-dev 
  exit 0
fi

