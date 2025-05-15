/*
  +----------------------------------------------------------------------+
  | PHP Version 7, 8                                                     |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2018 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: carl.guo a631929063@gmail.com                                |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_EBPF_H
#define PHP_EBPF_H

#include <iostream>
#include <unordered_set>

extern zend_module_entry ebpf_module_entry;
#define phpext_ebpf_ptr &ebpf_module_entry

#define PHP_EBPF_VERSION "1.0.0" /* Replace with version number for your extension */

#ifdef PHP_WIN32
#	define PHP_EBPF_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_EBPF_API __attribute__ ((visibility("default")))
#else
#	define PHP_EBPF_API
#endif

extern "C" {

#ifdef ZTS
#include "TSRM.h"
#endif
}

// Common definitions
#define TRACE_PIPE_PATH "/sys/kernel/debug/tracing/trace_pipe"
#define DEBUGFS "/sys/kernel/debug"
#define EXT_NAME "ebpf"
#define EXT_VERSION "1.0.0"

#define REGISTER_BPF_CLASS(ce, create_obj, php_class_name, cls, method) \
    INIT_CLASS_ENTRY(ce, php_class_name, method); \
    ce.create_object = create_obj; \
    cls = zend_register_internal_class(&ce);

// Common constants
const std::vector<std::string> syscall_prefixes = {
		"sys_",
		"__x64_sys_",
		"__x32_compat_sys_",
		"__ia32_compat_sys_",
		"__arm64_sys_",
		"__s390x_sys_",
		"__s390_sys_",
		"__riscv_sys_"
};

void callbackfn(void *cookie, void *data, int data_size);

class EbpfExtension {
private:
	void *mod;

public:
	zval _class_perf_event_obj;
	ebpf::BPF bpf;

	/**
	 * @brief Default constructor for EbpfExtension
	 */
	EbpfExtension() {
		ZVAL_UNDEF(&_class_perf_event_obj);
	};

	/**
	 * @brief Virtual destructor for EbpfExtension
	 */
	virtual ~EbpfExtension() {
		if (Z_TYPE(_class_perf_event_obj) != IS_UNDEF) {
			zval_ptr_dtor(&_class_perf_event_obj);
		}
	};

	ebpf::StatusTuple init(const std::string &bpf_program) {
		auto res = this->bpf.init(bpf_program);
		if (res.code() == 0)
			this->mod = (void *) this->bpf.get_mod();
		return res;
	}

	/**
	 * @brief Add a prefix to a function name
	 * @param prefix The prefix to add
	 * @param name The original function name
	 * @return The function name with prefix added
	 */
	static std::string add_prefix(const std::string &prefix, const std::string &name);

	/**
	 * @brief Fix syscall function name by adding appropriate prefix
	 * @param name The original syscall function name
	 * @return The fixed syscall function name with proper prefix
	 */
	std::string fix_syscall_fnname(const std::string &name);

	/**
	 * @brief Automatically load trace functions
	 * This method is responsible for loading and initializing trace-related functions
	 */
	void _trace_autoload();

	/**
	 * @brief Get kprobe functions matching a regular expression
	 * @param event_re Regular expression to match function names
	 * @return Set of matching function names
	 */
	std::unordered_set<std::string> get_kprobe_functions(const std::string &event_re);

	/**
	 * @brief Attach a kfunc (kernel function) probe
	 * @param kfn The kernel function name to attach to
	 * @return Status tuple indicating success or failure
	 */
	ebpf::StatusTuple attach_kfunc(const std::string &kfn);

	/**
	 * @brief Attach an LSM (Linux Security Module) probe
	 * @param lsm The LSM hook name to attach to
	 * @return Status tuple indicating success or failure
	 */
	ebpf::StatusTuple attach_lsm(const std::string &lsm);

	/**
	 * @brief Get a BPF table class
	 * @param table_name Name of the BPF table
	 * @param from_attr Attribute to get from the table
	 * @return The table class object
	 */
	zval get_table_cls(const char *table_name, int from_attr);
};

class BPFProgType {
public:
	static constexpr int SOCKET_FILTER = 1;
	static constexpr int KPROBE = 2;
	static constexpr int SCHED_CLS = 3;
	static constexpr int SCHED_ACT = 4;
	static constexpr int TRACEPOINT = 5;
	static constexpr int XDP = 6;
	static constexpr int PERF_EVENT = 7;
	static constexpr int CGROUP_SKB = 8;
	static constexpr int CGROUP_SOCK = 9;
	static constexpr int LWT_IN = 10;
	static constexpr int LWT_OUT = 11;
	static constexpr int LWT_XMIT = 12;
	static constexpr int SOCK_OPS = 13;
	static constexpr int SK_SKB = 14;
	static constexpr int CGROUP_DEVICE = 15;
	static constexpr int SK_MSG = 16;
	static constexpr int RAW_TRACEPOINT = 17;
	static constexpr int CGROUP_SOCK_ADDR = 18;
	static constexpr int CGROUP_SOCKOPT = 25;
	static constexpr int TRACING = 26;
	static constexpr int LSM = 29;
};


#define REGISTER_BPF_CONST(name) \
    zend_declare_class_constant_long(bpf_ce, #name, sizeof(#name) - 1, BPFProgType::name)

/*
  	Declare any global variables you may need between the BEGIN
	and END macros here:

ZEND_BEGIN_MODULE_GLOBALS(ebpf)
	zend_long  global_value;
	char *global_string;
ZEND_END_MODULE_GLOBALS(ebpf)
*/

/* Always refer to the globals in your function as EBPF_G(variable).
   You are encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/
#define EBPF_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(ebpf, v)

#if defined(ZTS) && defined(COMPILE_DL_EBPF)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif    /* PHP_EBPF_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
