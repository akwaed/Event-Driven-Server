# list all your source code files on the next line, replacing "<file1.c>",
# <file2.c>, etc.
CFILES = project4.c csapp.c
CFLAGS = -Wall -g

all:    p4server
# if you don't have a special "p4.h" file, delete "p4.h" from ALL
# the lines below
p4server:     p4.h $(CFILES)
    gcc $(CFLAGS) -o p4server $(CFILES)

# To create the tarball to turn in:
# 1. create a file "cookie.txt", containing the cookie string your
# client received from the test server.
# 2. type "make p4.tar"
p4turnin:
    mkdir p4turnin

p4.tar: p4turnin p4.h $(CFILES) cookie.txt
    cp p4.h $(CFILES) cookie.txt Makefile p4turnin
    tar cvf p4.tar p4turnin