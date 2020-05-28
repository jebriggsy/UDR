#include "udr_exception.h"
#include <sstream>
#include <cstring>
#include <errno.h>


udr_sysexception::udr_sysexception(const std::string &message) : udr_sysexception(errno, message)
{
}

udr_sysexception::udr_sysexception(int errnum, const std::string &message)
{
	std::ostringstream s;
	s << "(error " << errnum << ":" << strerror(errnum) << ") " << message;
	msg = s.str();
}

const char *udr_exception::what() const noexcept
{
	return msg.c_str();
}