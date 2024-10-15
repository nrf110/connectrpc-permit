#!/usr/bin/env zsh

rm -f git.env
echo "GIT_EMAIL=\"$(git config get --global user.email)\"" >> git.env
echo "GIT_NAME=\"$(git config get --global user.name)\"" >> git.env