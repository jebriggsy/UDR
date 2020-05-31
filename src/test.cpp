#include <thread>
#include <iostream>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#include <mutex>
#include <condition_variable>
#include <set>
#include <chrono>

using namespace std;

mutex m;
condition_variable cv;
std::set<pid_t> pids;

void foo(int n, siginfo_t *info, void *p)
{
	unique_lock<mutex> l(m);
	pids.insert(info->si_pid);
	cv.notify_all();
}

bool waitfor(pid_t p, int ms)
{
	unique_lock<mutex> l(m);
	bool ok = cv.wait_for(l, std::chrono::milliseconds(ms), [&]{return pids.count(p)>0;});
	if (ok)
		pids.erase(p);
	return ok;
}

pid_t child()
{
	pid_t p = fork();
	if (p == 0) {
		sleep(1);
		cout << "child exit"<<endl;
		exit(0);
	}
	return p;
}

void wait(pid_t p)
{
	bool ok = waitfor(p, 2000);
	cout << "waitfor return " << ok << " tid " << std::this_thread::get_id() <<endl;

}

void wait2(pid_t)
{
	sigset_t oldset, newset;
	sigemptyset(&newset);
	sigaddset(&newset, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &newset, &oldset);

	struct timespec ts;
	ts.tv_sec = 2;
	ts.tv_nsec = 0;
	int r = ppoll(nullptr, 0, &ts, &oldset);
	int e = errno;
	pthread_sigmask(SIG_SETMASK, &oldset, nullptr);

	cout << "poll return " << r << " e " << errno <<endl;
}

void test()
{
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_sigaction = foo;
	act.sa_flags = SA_SIGINFO;
	sigaction(SIGCHLD, &act, 0);


	pid_t p = child();
	cout << "cid is "<<p << " main tid " << std::this_thread::get_id()<<endl;

	std::thread thread(wait, p);
	sleep(1);
	sleep(1);
	sleep(1);
	wait(p);
	thread.join();
}



int main(int argc, char *argv[])
{
	test();
}
