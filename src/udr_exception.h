// udr_exception.h
// define excetptions encountered by udr
#include <exception>
#include <string>


class udr_exception : public std::exception
{
public:
    udr_exception() = default;
    udr_exception(const std::string &in_msg) : msg(in_msg) {}
    udr_exception(const char *in_msg) : msg(in_msg) {};

    virtual const char *what() const noexcept override;
protected:
    std::string msg;
};

class udr_exitexception : public udr_exception
{
public:
    udr_exitexception(int e)  : exitval(e) {}
    const int exitval;
};
    
class udr_argexception : public udr_exception
{
public:
    using udr_exception::udr_exception;
};

class udr_sysexception : public udr_exception
{
public:
    using udr_exception::udr_exception;
    udr_sysexception(int errnum, const std::string &message);
    udr_sysexception(const std::string &message);
};