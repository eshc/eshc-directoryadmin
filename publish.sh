#!/bin/sh
dotnet publish -c Release
pushd bin/Release/netcoreapp2.1/
rm -f ../../../eshc-diradmin-release.tar.xz
tar cJvf ../../../eshc-diradmin-release.tar.xz publish
popd
