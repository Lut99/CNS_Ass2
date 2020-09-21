#!/bin/bash

rsync -ruv {Makefile,src,go.sh} CNS:asg2/ --delete
