#!/bin/bash
which jq > /dev/null 2>&1
if [[ $? != 0 ]] ; then
	apk update > /dev/null 2>&1
	apk add --no-cache -q jq > /dev/null 2>&1
fi
curl -Ls https://raw.githubusercontent.com/home-assistant/hassio/master/version.json | jq -r ".homeassistant"
exit