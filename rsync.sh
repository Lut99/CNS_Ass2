#!/bin/bash

rsync -ruv {Makefile,src} CNS:asg2/ --delete
