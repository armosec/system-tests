#!/bin/bash

res=$(cat httpd-proxy.crt  | base64 -w 0 -)
echo $res

