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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


extern "C" {
#include "php.h"
#include "wrapper.h"
#include "php_ini.h"
#include "ext/standard/info.h"
}

#include "BPF.h"
#include "php_ebpf.h"
#include "bcc_common.h"
#include <string>
#include <fstream>
#include <sstream>
#include <regex>
#include <iomanip>

/* Handlers */
zend_object_handlers bpf_object_handlers;
zend_object_handlers table_object_handlers;

/* Class entries */
zend_class_entry *bpf_ce;
zend_class_entry *perf_event_array_table_ce;
zend_class_entry *hash_table_ce;
zend_class_entry *array_table_ce;
zend_class_entry *prog_array_table_ce;
zend_class_entry *per_cpu_hash_table_ce;
zend_class_entry *per_cpu_array_table_ce;
zend_class_entry *lpm_trie_table_ce;
zend_class_entry *stack_trace_table_ce;
zend_class_entry *lru_hash_table_ce;
zend_class_entry *lru_per_cpu_hash_table_ce;
zend_class_entry *cgroup_array_table_ce;
zend_class_entry *dev_map_table_ce;
zend_class_entry *cpu_map_table_ce;
zend_class_entry *xsk_map_table_ce;
zend_class_entry *map_in_map_array_table_ce;
zend_class_entry *map_in_map_hash_table_ce;
zend_class_entry *queue_stack_table_ce;
zend_class_entry *ring_buf_table_ce;
zend_class_entry *bpf_prog_func_ce;

/* Objects */
typedef struct _bpf_object {
	EbpfExtension *ebpf_cpp_cls;
	zend_object std;
} bpf_object;

typedef struct _sub_object {
	ebpf::BPF *bpf;
	zend_object std;
} sub_object;

std::string cb_fn;

void callbackfn(void *cookie, void *data, int data_size) {
	zval params[3];
	zval retval;

	ZVAL_LONG(&params[0], 0);
	ZVAL_STRINGL(&params[1], (const char *) data, data_size);
	ZVAL_LONG(&params[2], data_size);
	zval function_name;
	ZVAL_STRING(&function_name, cb_fn.c_str());
	if (call_user_function(EG(function_table), nullptr, &function_name, &retval, 3, params) == SUCCESS) {
		zval_ptr_dtor(&retval);
	} else {
		php_error_docref(NULL, E_WARNING, "Failed to call callback function '%s'", cb_fn.c_str());
	}


	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);
	zval_ptr_dtor(&params[2]);
	zval_ptr_dtor(&function_name);
}

static inline bpf_object *bpf_fetch_object(zend_object *obj) {
	return (bpf_object *) ((char *) (obj) - XtOffsetOf(bpf_object, std));
}

static inline sub_object *table_fetch_object(zend_object *obj) {
	return (sub_object *) ((char *) (obj) - XtOffsetOf(sub_object, std));
}

void EbpfExtension::_trace_autoload() {
	size_t num_funcs = bpf_num_functions(mod);
	for (size_t i = 0; i < num_funcs; i++) {
		const char *func_name = bpf_function_name(mod, i);
		std::string fn_name(func_name);
		if (fn_name.rfind("kprobe__", 0) == 0) {
			std::string kernel_func = fix_syscall_fnname(fn_name.substr(8));
			bpf.attach_kprobe(kernel_func, fn_name);
		} else if (fn_name.rfind("kretprobe__", 0) == 0) {
			std::string kernel_func = fix_syscall_fnname(fn_name.substr(11));
			bpf.attach_kprobe(kernel_func, fn_name, 0, BPF_PROBE_RETURN);
		} else if (fn_name.rfind("tracepoint__", 0) == 0) {
			std::string tp_name = fn_name.substr(12);
			size_t sep = tp_name.find("__");
			if (sep != std::string::npos) {
				tp_name.replace(sep, 2, ":");
			}
			bpf.attach_tracepoint(tp_name, fn_name);
		} else if (fn_name.rfind("raw_tracepoint__", 0) == 0) {
			std::string tp_name = fn_name.substr(16);
			bpf.attach_raw_tracepoint(tp_name, fn_name);
		} else if (fn_name.rfind("kfunc__", 0) == 0) {
			fn_name = add_prefix("kfunc__", fn_name);
			attach_kfunc(fn_name);
		} else if (fn_name.rfind("kretfunc__", 0) == 0) {
			fn_name = add_prefix("kretfunc__", fn_name);
			this->attach_kfunc(fn_name);
		} else if (fn_name.rfind("lsm__", 0) == 0) {
			fn_name = add_prefix("lsm__", fn_name);
			this->attach_lsm(fn_name);
		}
	}
}

std::string EbpfExtension::add_prefix(const std::string &prefix, const std::string &name) {
	if (name.rfind(prefix, 0) != 0) {
		return prefix + name;
	}
	return name;
}

std::string EbpfExtension::fix_syscall_fnname(const std::string &name) {
	for (const auto &prefix: syscall_prefixes) {
		if (name.rfind(prefix, 0) == 0) {
			return bpf.get_syscall_fnname(name.substr(prefix.length()));
		}
	}
	return name;
}

zval EbpfExtension::get_table_cls(const char *table_name, int from_attr) {
	zval retval;
	ZVAL_NULL(&retval);

	int ttype = bpf_table_type(this->mod, table_name);

	switch (ttype) {
		case BPF_MAP_TYPE_HASH: {
			if (!hash_table_ce) {
				zend_throw_error(NULL, "HashTable class not found");
				return retval;
			}
			object_init_ex(&retval, hash_table_ce);
			sc_zend_update_property_string(hash_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_ARRAY: {
			if (!array_table_ce) {
				zend_throw_error(NULL, "ArrayTable class not found");
				return retval;
			}
			object_init_ex(&retval, array_table_ce);
			sc_zend_update_property_string(array_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_PROG_ARRAY: {
			if (!prog_array_table_ce) {
				zend_throw_error(NULL, "ProgArrayTable class not found");
				return retval;
			}
			object_init_ex(&retval, prog_array_table_ce);
			sc_zend_update_property_string(prog_array_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
			if (Z_TYPE(_class_perf_event_obj) != IS_UNDEF) {
				ZVAL_COPY(&retval, &_class_perf_event_obj);
				return retval;
			}
			if (!perf_event_array_table_ce) {
				zend_throw_error(NULL, "PerfEventArrayTable class not found");
				return retval;
			}
			object_init_ex(&retval, perf_event_array_table_ce);
			sc_zend_update_property_string(perf_event_array_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			ZVAL_COPY(&_class_perf_event_obj, &retval);
			return retval;
		}
		case BPF_MAP_TYPE_PERCPU_HASH: {
			if (!per_cpu_hash_table_ce) {
				zend_throw_error(NULL, "PerCpuHashTable class not found");
				return retval;
			}
			object_init_ex(&retval, per_cpu_hash_table_ce);
			sc_zend_update_property_string(per_cpu_hash_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_PERCPU_ARRAY: {
			if (!per_cpu_array_table_ce) {
				zend_throw_error(NULL, "PerCpuArrayTable class not found");
				return retval;
			}
			object_init_ex(&retval, per_cpu_array_table_ce);
			sc_zend_update_property_string(per_cpu_array_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_LPM_TRIE: {
			if (!lpm_trie_table_ce) {
				zend_throw_error(NULL, "LpmTrieTable class not found");
				return retval;
			}
			object_init_ex(&retval, lpm_trie_table_ce);
			sc_zend_update_property_string(lpm_trie_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_STACK_TRACE: {
			if (!stack_trace_table_ce) {
				zend_throw_error(NULL, "StackTraceTable class not found");
				return retval;
			}
			object_init_ex(&retval, stack_trace_table_ce);
			sc_zend_update_property_string(stack_trace_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_LRU_HASH: {
			if (!lru_hash_table_ce) {
				zend_throw_error(NULL, "LruHashTable class not found");
				return retval;
			}
			object_init_ex(&retval, lru_hash_table_ce);
			sc_zend_update_property_string(lru_hash_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_LRU_PERCPU_HASH: {
			if (!lru_per_cpu_hash_table_ce) {
				zend_throw_error(NULL, "LruPerCpuHashTable class not found");
				return retval;
			}
			object_init_ex(&retval, lru_per_cpu_hash_table_ce);
			sc_zend_update_property_string(lru_per_cpu_hash_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_CGROUP_ARRAY: {
			if (!cgroup_array_table_ce) {
				zend_throw_error(NULL, "CgroupArrayTable class not found");
				return retval;
			}
			object_init_ex(&retval, cgroup_array_table_ce);
			sc_zend_update_property_string(cgroup_array_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_DEVMAP: {
			if (!dev_map_table_ce) {
				zend_throw_error(NULL, "DevMapTable class not found");
				return retval;
			}
			object_init_ex(&retval, dev_map_table_ce);
			sc_zend_update_property_string(dev_map_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_CPUMAP: {
			if (!cpu_map_table_ce) {
				zend_throw_error(NULL, "CpuMapTable class not found");
				return retval;
			}
			object_init_ex(&retval, cpu_map_table_ce);
			sc_zend_update_property_string(cpu_map_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_XSKMAP: {
			if (!xsk_map_table_ce) {
				zend_throw_error(NULL, "XskMapTable class not found");
				return retval;
			}
			object_init_ex(&retval, xsk_map_table_ce);
			sc_zend_update_property_string(xsk_map_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_ARRAY_OF_MAPS: {
			if (!map_in_map_array_table_ce) {
				zend_throw_error(NULL, "MapInMapArrayTable class not found");
				return retval;
			}
			object_init_ex(&retval, map_in_map_array_table_ce);
			sc_zend_update_property_string(map_in_map_array_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_HASH_OF_MAPS: {
			if (!map_in_map_hash_table_ce) {
				zend_throw_error(NULL, "MapInMapHashTable class not found");
				return retval;
			}
			object_init_ex(&retval, map_in_map_hash_table_ce);
			sc_zend_update_property_string(map_in_map_hash_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
		case BPF_MAP_TYPE_QUEUE:
		case BPF_MAP_TYPE_STACK: {
			if (!queue_stack_table_ce) {
				zend_throw_error(NULL, "QueueStackTable class not found");
				return retval;
			}
			object_init_ex(&retval, queue_stack_table_ce);
			sc_zend_update_property_string(queue_stack_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
#ifdef BPF_MAP_TYPE_RINGBUF
		case BPF_MAP_TYPE_RINGBUF: {
			if (!ring_buf_table_ce) {
				zend_throw_error(NULL, "RingBufTable class not found");
				return retval;
			}
			object_init_ex(&retval, ring_buf_table_ce);
			sc_zend_update_property_string(ring_buf_table_ce, &retval, "name", sizeof("name") - 1, table_name);
			sub_object *table_obj = table_fetch_object(Z_OBJ(retval));
			table_obj->bpf = &this->bpf;
			Z_ADDREF(retval);
			break;
		}
#endif
		default:
			if (from_attr) {
				ZVAL_LONG(&retval, ttype);
			}
			zend_throw_error(NULL, "Unknown table type %d", ttype);
			return retval;
	}

	return retval;
}

std::unordered_set<std::string> EbpfExtension::get_kprobe_functions(const std::string &event_re) {
	std::unordered_set<std::string> blacklist;
	std::unordered_set<std::string> avail_filter;
	std::unordered_set<std::string> fns;

	std::string blacklist_file = std::string(DEBUGFS) + "/kprobes/blacklist";
	std::ifstream blacklist_f(blacklist_file);
	if (blacklist_f.is_open()) {
		std::string line;
		while (std::getline(blacklist_f, line)) {
			std::istringstream iss(line);
			std::string addr, func_name;
			if (iss >> addr >> func_name) {
				blacklist.insert(func_name);
			}
		}
		blacklist_f.close();
	}

	std::string avail_filter_file = std::string(DEBUGFS) + "/tracing/available_filter_functions";
	std::ifstream avail_filter_f(avail_filter_file);
	if (avail_filter_f.is_open()) {
		std::string line;
		while (std::getline(avail_filter_f, line)) {
			std::istringstream iss(line);
			std::string func_name;
			if (iss >> func_name) {
				avail_filter.insert(func_name);
			}
		}
		avail_filter_f.close();
	}

	std::ifstream kallsyms_f("/proc/kallsyms");
	if (!kallsyms_f.is_open()) {
		std::cerr << "Failed to open /proc/kallsyms\n";
		return fns;
	}

	std::string line;
	bool in_init_section = false;
	bool in_irq_section = false;
	std::regex cold_regex(".*\\.cold(\\.\\d+)?$");

	while (std::getline(kallsyms_f, line)) {
		std::istringstream iss(line);
		std::string addr, type, func_name;
		if (!(iss >> addr >> type >> func_name)) {
			continue;
		}

		if (!in_init_section) {
			if (func_name == "__init_begin") {
				in_init_section = true;
				continue;
			}
		} else if (func_name == "__init_end") {
			in_init_section = false;
			continue;
		}

		if (!in_irq_section) {
			if (func_name == "__irqentry_text_start") {
				in_irq_section = true;
				continue;
			} else if (func_name == "__irqentry_text_end") {
				in_irq_section = false;
				continue;
			}
		} else if (func_name == "__irqentry_text_end") {
			in_irq_section = false;
			continue;
		}

		if (func_name.rfind("_kbl_addr_", 0) == 0) {
			continue;
		}
		if (func_name.rfind("__perf", 0) == 0 || func_name.rfind("perf_", 0) == 0) {
			continue;
		}
		if (func_name.rfind("__SCT__", 0) == 0) {
			continue;
		}
		if (std::regex_match(func_name, cold_regex)) {
			continue;
		}

		if ((type == "t" || type == "T" || type == "w" || type == "W") &&
		    func_name == event_re &&
		    blacklist.find(func_name) == blacklist.end() &&
		    avail_filter.find(func_name) != avail_filter.end()) {
			fns.insert(func_name);
		}
	}

	return fns;
}

#ifdef BPF_PROG_TYPE_TRACING
ebpf::StatusTuple EbpfExtension::attach_kfunc(const std::string &kfn) {
	int probe_fd;
	auto fn = bpf.load_func(kfn, BPF_PROG_TYPE_TRACING, probe_fd);

	int res_fd = bpf_attach_kfunc(probe_fd);
	if (res_fd < 0) {
		TRY2(bpf.unload_func(kfn));
		return ebpf::StatusTuple(-1, "Unable to attach kfunc using %s",
								 kfn.c_str());
	}
	return ebpf::StatusTuple::OK();
}
#else

ebpf::StatusTuple EbpfExtension::attach_kfunc(const std::string &kfn) {
	return ebpf::StatusTuple(-1,
	                         "kfunc attachment requires BPF_PROG_TYPE_TRACING, which is not available on this kernel");
}

#endif

#ifdef BPF_PROG_TYPE_LSM
ebpf::StatusTuple EbpfExtension::attach_lsm(const std::string &lsm) {
	int probe_fd;
	auto fn = bpf.load_func(lsm, BPF_PROG_TYPE_LSM, probe_fd);

	int res_fd = bpf_attach_lsm(probe_fd);
	if (res_fd < 0) {
		TRY2(bpf.unload_func(lsm));
		return ebpf::StatusTuple(-1, "Unable to attach lsm using %s",
								 lsm.c_str());
	}
	return ebpf::StatusTuple::OK();
}
#else

ebpf::StatusTuple EbpfExtension::attach_lsm(const std::string &lsm) {
	return ebpf::StatusTuple(-1, "BPF_PROG_TYPE_LSM is not supported by this kernel.");
}

#endif


zend_object *bpf_create_object(zend_class_entry *ce) {
	bpf_object *intern = (bpf_object *) ecalloc(1, sizeof(bpf_object) + zend_object_properties_size(ce));
	intern->ebpf_cpp_cls = new EbpfExtension();
	zend_object_std_init(&intern->std, ce);
	object_properties_init(&intern->std, ce);
	intern->std.handlers = &bpf_object_handlers;
	return &intern->std;
}

void bpf_free_object(zend_object *object) {
	bpf_object *intern = bpf_fetch_object(object);
	zend_object_std_dtor(&intern->std);
}

zend_object *table_create_object(zend_class_entry *ce) {
	sub_object *intern = (sub_object *) ecalloc(1, sizeof(sub_object) + zend_object_properties_size(ce));
	zend_object_std_init(&intern->std, ce);
	object_properties_init(&intern->std, ce);
	intern->std.handlers = &table_object_handlers;
	return &intern->std;
}

void table_free_object(zend_object *object) {
	sub_object *intern = table_fetch_object(object);
	zend_object_std_dtor(&intern->std);
}

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("ebpf.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_ebpf_globals, ebpf_globals)
    STD_PHP_INI_ENTRY("ebpf.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_ebpf_globals, ebpf_globals)
PHP_INI_END()
*/
/* }}} */

/* Remove the following function when you have successfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */



/* Every user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_ebpf_compiled(string arg)
   Return a string to confirm that the module is compiled in */

PHP_METHOD (Bpf, __construct) {
	zval *opts;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "a", &opts) == FAILURE) {
		zend_throw_error(NULL, "Expected options array");
		return;
	}

	if (Z_OBJCE_P(getThis()) != bpf_ce) {
		zend_throw_error(NULL, "Invalid object type");
		return;
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	zval *text = zend_hash_str_find(Z_ARRVAL_P(opts), "text", strlen("text"));

	if (text && Z_TYPE_P(text) == IS_STRING) {
		std::string source(Z_STRVAL_P(text), Z_STRLEN_P(text));
		if (!obj->ebpf_cpp_cls) {
			zend_throw_error(NULL, "Invalid internal C++ object");
			RETURN_NULL();
		}

		auto res = obj->ebpf_cpp_cls->init(source);
		if (res.code() != 0) {
			zend_throw_error(NULL, "BPF init failed: %s", res.msg().c_str());
			RETURN_FALSE;
		}
		obj->ebpf_cpp_cls->_trace_autoload();
	}

	RETURN_TRUE;
}

PHP_METHOD (Bpf, __get) {
	char *name;
	size_t name_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &name, &name_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	int from_attr = 1;
	zval table = obj->ebpf_cpp_cls->get_table_cls(name, from_attr);

	RETURN_ZVAL(&table, 1, 0);
}

PHP_METHOD (Bpf, get_kprobe_functions) {
	char *fn;
	size_t fn_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &fn, &fn_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto res = obj->ebpf_cpp_cls->get_kprobe_functions(std::string(fn, fn_len));

	array_init(return_value);
	for (const auto &item: res) {
		add_next_index_string(return_value, item.c_str());
	}
}

PHP_METHOD (Bpf, attach_kprobe) {
	char *kernel_func, *probe_func;
	size_t kernel_func_len, probe_func_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &kernel_func, &kernel_func_len,
	                          &probe_func, &probe_func_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto attach_res = obj->ebpf_cpp_cls->bpf.attach_kprobe(
			std::string(kernel_func, kernel_func_len),
			std::string(probe_func, probe_func_len)
	);

	if (attach_res.code() != 0) {
		zend_throw_error(NULL, "attach error: %s", attach_res.msg().c_str());
		RETURN_NULL();
	}

	RETURN_TRUE;
}

PHP_METHOD (Bpf, attach_tracepoint) {
	char *tp_func, *probe_func;
	size_t tp_func_len, probe_func_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &tp_func, &tp_func_len,
	                          &probe_func, &probe_func_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto attach_res = obj->ebpf_cpp_cls->bpf.attach_tracepoint(
			std::string(tp_func, tp_func_len),
			std::string(probe_func, probe_func_len)
	);

	if (attach_res.code() != 0) {
		zend_throw_error(NULL, "attach error: %s", attach_res.msg().c_str());
		RETURN_NULL();
	}

	RETURN_TRUE;
}

PHP_METHOD (Bpf, attach_raw_tracepoint) {
	char *tp_func, *probe_func;
	size_t tp_func_len, probe_func_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &tp_func, &tp_func_len,
	                          &probe_func, &probe_func_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto attach_res = obj->ebpf_cpp_cls->bpf.attach_raw_tracepoint(
			std::string(tp_func, tp_func_len),
			std::string(probe_func, probe_func_len)
	);

	if (!attach_res.ok()) {
		zend_throw_error(NULL, "attach error: %s", attach_res.msg().c_str());
		RETURN_NULL();
	}

	RETURN_TRUE;
}

PHP_METHOD (Bpf, attach_kfunc) {
	char *kfunc;
	size_t kfunc_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &kfunc, &kfunc_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto attach_res = obj->ebpf_cpp_cls->attach_kfunc(std::string(kfunc, kfunc_len));

	if (attach_res.code() != 0) {
		zend_throw_error(NULL, "attach error: %s", attach_res.msg().c_str());
		RETURN_NULL();
	}

	RETURN_TRUE;
}

PHP_METHOD (Bpf, attach_lsm) {
	char *lsm;
	size_t lsm_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &lsm, &lsm_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto attach_res = obj->ebpf_cpp_cls->attach_lsm(std::string(lsm, lsm_len));

	if (attach_res.code() != 0) {
		zend_throw_error(NULL, "attach error: %s", attach_res.msg().c_str());
		RETURN_NULL();
	}

	RETURN_TRUE;
}

PHP_METHOD (Bpf, attach_uprobe) {
	char *binary_path, *symbol, *probe_func;
	size_t binary_path_len, symbol_len, probe_func_len;
	zval *options = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss|a",
	                          &binary_path, &binary_path_len,
	                          &symbol, &symbol_len,
	                          &probe_func, &probe_func_len,
	                          &options) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	int64_t symbol_addr = 0, symbol_offset = 0, pid_param = 0;
	uint32_t ref_ctr_offset = 0;
	pid_t pid = -1;

	if (options && Z_TYPE_P(options) == IS_ARRAY) {
		zval *tmp;

		if ((tmp = zend_hash_str_find(Z_ARRVAL_P(options), "symbol_addr", strlen("symbol_addr"))) != NULL) {
			symbol_addr = zval_get_long(tmp);
		}

		if ((tmp = zend_hash_str_find(Z_ARRVAL_P(options), "symbol_offset", strlen("symbol_offset"))) != NULL) {
			symbol_offset = zval_get_long(tmp);
		}

		if ((tmp = zend_hash_str_find(Z_ARRVAL_P(options), "ref_ctr_offset", strlen("ref_ctr_offset"))) != NULL) {
			ref_ctr_offset = (uint32_t) zval_get_long(tmp);
		}

		if ((tmp = zend_hash_str_find(Z_ARRVAL_P(options), "pid", strlen("pid"))) != NULL) {
			pid_param = zval_get_long(tmp);
			if (pid_param > 0) {
				pid = static_cast<pid_t>(pid_param);
			}
		}
	}

	auto attach_res = obj->ebpf_cpp_cls->bpf.attach_uprobe(
			std::string(binary_path, binary_path_len),
			std::string(symbol, symbol_len),
			std::string(probe_func, probe_func_len),
			symbol_addr,
			BPF_PROBE_ENTRY,
			pid,
			symbol_offset,
			ref_ctr_offset
	);

	if (!attach_res.ok()) {
		zend_throw_error(NULL, "attach_uprobe error: %s", attach_res.msg().c_str());
		RETURN_NULL();
	}
	RETURN_TRUE;
}

PHP_METHOD (Bpf, detach_kprobe) {
	char *fn;
	size_t fn_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &fn, &fn_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto detach_res = obj->ebpf_cpp_cls->bpf.detach_kprobe(std::string(fn, fn_len));

	if (detach_res.code() != 0) {
		zend_throw_error(NULL, "detach_kprobe error: %s", detach_res.msg().c_str());
		RETURN_NULL();
	}

	RETURN_TRUE;
}

PHP_METHOD (Bpf, detach_uprobe) {
	char *binary_path, *symbol;
	size_t binary_path_len, symbol_len;
	zval *options = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|a",
	                          &binary_path, &binary_path_len,
	                          &symbol, &symbol_len,
	                          &options) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	int64_t symbol_addr = 0, symbol_offset = 0, pid_param = 0;
	pid_t pid = -1;

	if (options && Z_TYPE_P(options) == IS_ARRAY) {
		zval *tmp;

		if ((tmp = zend_hash_str_find(Z_ARRVAL_P(options), "symbol_addr", strlen("symbol_addr"))) != NULL) {
			symbol_addr = zval_get_long(tmp);
		}

		if ((tmp = zend_hash_str_find(Z_ARRVAL_P(options), "symbol_offset", strlen("symbol_offset"))) != NULL) {
			symbol_offset = zval_get_long(tmp);
		}

		if ((tmp = zend_hash_str_find(Z_ARRVAL_P(options), "pid", strlen("pid"))) != NULL) {
			pid_param = zval_get_long(tmp);
			if (pid_param > 0) {
				pid = static_cast<pid_t>(pid_param);
			}
		}
	}

	auto detach_res = obj->ebpf_cpp_cls->bpf.detach_uprobe(
			std::string(binary_path, binary_path_len),
			std::string(symbol, symbol_len),
			symbol_addr,
			BPF_PROBE_ENTRY,
			pid,
			symbol_offset
	);

	if (detach_res.code() != 0) {
		zend_throw_error(NULL, "detach_uprobe error: %s", detach_res.msg().c_str());
		RETURN_NULL();
	}
	RETURN_TRUE;
}

PHP_METHOD (Bpf, trace_print) {
	char *fmt = NULL;
	size_t fmt_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|s", &fmt, &fmt_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	std::ifstream pipe(TRACE_PIPE_PATH);
	if (!pipe.is_open()) {
		zend_throw_error(NULL, "Failed to open trace_pipe");
		RETURN_NULL();
	}

	std::string line;
	while (true) {
		if (!std::getline(pipe, line)) {
			continue;
		}
		if (line.empty() || line.rfind("CPU:", 0) == 0) {
			continue;
		}

		std::string task = line.substr(0, 16);
		task.erase(0, task.find_first_not_of(" "));

		std::istringstream iss(line.substr(17));
		std::string pid, cpu, flags, ts, msg;
		char delim;

		if (!(iss >> pid >> delim >> cpu >> delim >> flags >> ts)) {
			continue;
		}

		size_t sym_end = iss.str().find(": ", iss.tellg());
		if (sym_end != std::string::npos) {
			msg = iss.str().substr(sym_end + 2);
		}

		std::vector<std::string> fields = {task, pid, cpu, flags, ts, msg};
		if (fmt == NULL) {
			php_printf("%s\n", line.c_str());
		} else {
			std::string output(fmt, fmt_len);
			std::regex pattern(R"(\{(\d+)\})");
			std::smatch match;
			while (std::regex_search(output, match, pattern)) {
				int index = std::stoi(match[1]);
				std::string replacement = (index >= 0 && index < (int) fields.size()) ? fields[index] : "";
				output.replace(match.position(0), match.length(0), replacement);
			}
			php_printf("%s\n", output.c_str());
		}
	}
}

PHP_METHOD (Bpf, trace_fields) {
	std::ifstream traceFile(TRACE_PIPE_PATH);
	if (!traceFile.is_open()) {
		zend_throw_error(NULL, "Failed to open trace_pipe");
		RETURN_NULL();
	}

	std::string line;
	while (std::getline(traceFile, line)) {
		if (line.empty() || line.rfind("CPU:", 0) == 0) {
			continue;
		}

		std::string task = line.substr(0, 16);
		task.erase(0, task.find_first_not_of(' '));

		std::istringstream iss(line.substr(17));
		std::string pid, cpu, flags, ts, msg;
		char delim;

		if (!(iss >> pid >> delim >> cpu >> delim >> flags >> ts)) {
			continue;
		}

		size_t sym_end = iss.str().find(": ", iss.tellg());
		if (sym_end != std::string::npos) {
			msg = iss.str().substr(sym_end + 2);
		}

		array_init(return_value);
		add_index_string(return_value, 0, task.c_str());
		add_index_long(return_value, 1, std::stoi(pid));
		add_index_long(return_value, 2, std::stoi(cpu.substr(1, cpu.size() - 2)));
		add_index_string(return_value, 3, flags.c_str());
		add_index_double(return_value, 4, std::stod(ts));
		add_index_stringl(return_value, 5, msg.c_str(), msg.size());

		return;
	}

	RETURN_NULL();
}

PHP_METHOD (Bpf, get_table) {
	char *table_name;
	size_t table_name_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &table_name, &table_name_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	int from_fn = 0;
	auto table = obj->ebpf_cpp_cls->get_table_cls(table_name, from_fn);

	if (Z_TYPE(table) == IS_NULL) {
		RETURN_NULL();
	}

	RETURN_ZVAL(&table, 1, 0);
}

PHP_METHOD (Bpf, perf_buffer_poll) {
	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	zval *name_zv = sc_zend_read_property(perf_event_array_table_ce, &obj->ebpf_cpp_cls->_class_perf_event_obj, "name",
	                                      sizeof("name") - 1, 0);

	if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) {
		zend_throw_error(NULL, "Invalid or missing name property");
		RETURN_NULL();
	}
	int timeout_ms = -1;
	int res = obj->ebpf_cpp_cls->bpf.poll_perf_buffer(std::string(Z_STRVAL_P(name_zv), Z_STRLEN_P(name_zv)),
	                                                  timeout_ms);
	if (res < 0) {
		zend_throw_error(NULL, "perf buffer poll error.");
	}
}

PHP_METHOD (Bpf, get_syscall_fnname) {
	char *name;
	size_t name_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &name, &name_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	std::string result = obj->ebpf_cpp_cls->bpf.get_syscall_fnname(std::string(name, name_len));

	RETURN_STRING(result.c_str());
}

PHP_METHOD (Bpf, load_func) {
	char *fn;
	size_t fn_len;
	zend_long prog_type;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "sl", &fn, &fn_len, &prog_type) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	int probe_fd;
	auto res = obj->ebpf_cpp_cls->bpf.load_func(
			std::string(fn, fn_len),
			static_cast<bpf_prog_type>(prog_type),
			probe_fd
	);

	if (res.code() != 0) {
		zend_throw_error(NULL, "Failed to load function: %s", res.msg().c_str());
		RETURN_NULL();
	}

	object_init_ex(return_value, bpf_prog_func_ce);

	zval name_zv;
	ZVAL_STRINGL(&name_zv, fn, fn_len);
	sc_zend_update_property(bpf_prog_func_ce, return_value, "name", sizeof("name") - 1, &name_zv);
	zval_ptr_dtor(&name_zv);

	zval fd_zv;
	ZVAL_LONG(&fd_zv, probe_fd);
	sc_zend_update_property(bpf_prog_func_ce, return_value, "fd", sizeof("fd") - 1, &fd_zv);
}

PHP_METHOD (Bpf, attach_raw_socket) {
	zval *prog_fn;
	char *interface;
	size_t interface_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "os", &prog_fn, &interface, &interface_len) == FAILURE) {
		RETURN_NULL();
	}

	bpf_object *obj = bpf_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->ebpf_cpp_cls) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	if (Z_TYPE_P(prog_fn) != IS_OBJECT) {
		zend_throw_error(NULL, "First parameter must be a BPFProgFunction object");
		RETURN_NULL();
	}

	zval *fd = sc_zend_read_property(Z_OBJCE_P(prog_fn), prog_fn, "fd", strlen("fd"), 0);

	if (!fd || Z_TYPE_P(fd) != IS_LONG) {
		zend_throw_error(NULL, "Invalid BPFProgFunction object: missing or invalid fd property");
		RETURN_NULL();
	}

	int sock = bpf_open_raw_sock(interface);
	if (sock < 0) {
		zend_throw_error(NULL, "Failed to open raw socket on interface: %s", interface);
		RETURN_NULL();
	}

	int res = bpf_attach_socket(sock, Z_LVAL_P(fd));
	if (res < 0) {
		close(sock);
		zend_throw_error(NULL, "Failed to attach BPF program to socket");
		RETURN_NULL();
	}

	RETURN_TRUE;
}

PHP_METHOD (PerfEventArrayTable, open_perf_buffer) {
	char *cb_fn_str = NULL;
	size_t cb_fn_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &cb_fn_str, &cb_fn_len) == FAILURE) {
		RETURN_NULL();
	}

	zval *name_zv = sc_zend_read_property(Z_OBJCE_P(getThis()), getThis(), "name",
	                                      sizeof("name") - 1, 0);

	if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) {
		zend_throw_error(NULL, "Invalid or missing name property");
		RETURN_NULL();
	}

	const char *name = Z_STRVAL_P(name_zv);
	cb_fn = std::string(cb_fn_str, cb_fn_len);

	sub_object *obj = table_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->bpf) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto res = obj->bpf->open_perf_buffer(name, callbackfn);
	if (res.code() != 0) {
		zend_throw_error(NULL, "open_perf_buffer error: %s", res.msg().c_str());
		RETURN_NULL();
	}

	RETURN_TRUE;
}

PHP_METHOD (HashTable, values) {
	zval *name_zv = sc_zend_read_property(Z_OBJCE_P(getThis()), getThis(), "name",
	                                      sizeof("name") - 1, 0);

	if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) {
		zend_throw_error(NULL, "Invalid or missing name property");
		RETURN_NULL();
	}

	sub_object *obj = table_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->bpf) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	std::vector<std::pair<std::vector<char>, std::vector<char>>> entries;
	auto table = obj->bpf->get_table(Z_STRVAL_P(name_zv));
	auto status = table.get_table_offline_ptr(entries);

	if (status.code() != 0) {
		zend_throw_error(NULL, "Failed to get table values: %s", status.msg().c_str());
		RETURN_NULL();
	}

	array_init(return_value);

	for (const auto &pair: entries) {
		const auto &key_data = pair.first;
		const auto &val_data = pair.second;
		zval entry;
		array_init(&entry);
		add_assoc_stringl(&entry, "key", key_data.data(), key_data.size());
		add_assoc_stringl(&entry, "value", val_data.data(), val_data.size());
		add_next_index_zval(return_value, &entry);
	}
}

PHP_METHOD (HashTable, clear) {
	zval *name_zv = sc_zend_read_property(Z_OBJCE_P(getThis()), getThis(), "name",
	                                      sizeof("name") - 1, 0);

	if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) {
		zend_throw_error(NULL, "Invalid or missing name property");
		RETURN_NULL();
	}
	sub_object *obj = table_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->bpf) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto table = obj->bpf->get_table(Z_STRVAL_P(name_zv));
	auto res = table.clear_table_non_atomic();

	if (res.code() != 0) {
		zend_throw_error(NULL, "Failed to clear table: %s", res.msg().c_str());
		RETURN_NULL();
	}

	RETURN_TRUE;
}

PHP_METHOD (ArrayTable, get_value) {
	zend_long index;
//	zval name_rv;
//	zval *name_zv;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &index) == FAILURE) {
		RETURN_NULL();
	}
	zval *name_zv = sc_zend_read_property(Z_OBJCE_P(getThis()), getThis(), "name",
	                                      sizeof("name") - 1, 0);

	if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) {
		zend_throw_error(NULL, "Invalid or missing name property");
		RETURN_NULL();
	}

	sub_object *obj = table_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->bpf) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	try {
		auto table = obj->bpf->get_array_table<uint64_t>(Z_STRVAL_P(name_zv));
		uint64_t val;
		auto res = table.get_value(index, val);
		if (res.code() != 0) {
			zend_throw_error(NULL, "Get value error in %s", Z_STRVAL_P(name_zv));
			RETURN_NULL();
		}
		RETURN_LONG(val);
	} catch (const std::exception &e) {
		zend_throw_error(NULL, "Exception: %s", e.what());
		RETURN_NULL();
	}
}

PHP_METHOD (ArrayTable, print_log2_hist) {
	char *header;
	size_t header_len;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &header, &header_len) == FAILURE) {
		RETURN_NULL();
	}

	zval *name_zv = sc_zend_read_property(Z_OBJCE_P(getThis()), getThis(), "name",
	                                      sizeof("name") - 1, 0);


	if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) {
		zend_throw_error(NULL, "Invalid or missing name property");
		RETURN_NULL();
	}

	sub_object *obj = table_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->bpf) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto table = obj->bpf->get_array_table<uint64_t>(Z_STRVAL_P(name_zv));

	auto vals = table.get_table_offline();
	auto center_text = [](const std::string &text, int width) -> std::string {
		int len = static_cast<int>(text.length());
		if (width <= len) return text;
		int padding = width - len;
		int left = padding / 2;
		int right = padding - left;
		return std::string(left, ' ') + text + std::string(right, ' ');
	};
	auto stars = [](uint64_t val, uint64_t max_val, int width) -> std::string {
		std::string result;
		int limit = std::min(width, static_cast<int>((double) val * width / max_val));
		for (int i = 0; i < limit; ++i) {
			result += '*';
		}
		if (val > max_val && !result.empty()) {
			result.back() = '+';
		}
		return result;
	};

	int idx_max = -1;
	uint64_t val_max = 0;

	for (size_t i = 0; i < vals.size(); ++i) {
		if (vals[i] > 0) {
			idx_max = static_cast<int>(i);
			if (vals[i] > val_max) val_max = vals[i];
		}
	}

	if (idx_max == -1) {
		std::cout << "No data to display." << std::endl;
		RETURN_FALSE;
	}

	int stars_max = 40;
	bool long_format = idx_max > 32;

	int col1_width = long_format ? 41 : 27;
	int label_width = col1_width - 2;

	std::cout << center_text(header, label_width) << ": count    distribution" << std::endl;

	bool strip_leading_zero = true;
	for (int i = 1; i <= idx_max; ++i) {
		uint64_t low = (1ULL << (i - 1));
		uint64_t high = (1ULL << i) - 1;
		if (low == high) low -= 1;

		uint64_t val = vals[i];
		if (strip_leading_zero && val == 0) {
			continue;
		}
		strip_leading_zero = false;

		std::string bar = stars(val, val_max, stars_max);
		if (long_format) {
			std::cout << std::right << std::setw(20) << low << " -> "
			          << std::left << std::setw(20) << high << " : "
			          << std::setw(8) << val << "|" << bar << "|" << std::endl;
		} else {
			std::cout << std::right << std::setw(10) << low << " -> "
			          << std::left << std::setw(10) << high << " : "
			          << std::setw(8) << val << "|" << bar << "|" << std::endl;
		}
	}

	RETURN_FALSE;
}

PHP_METHOD (ArrayTable, print_linear_hist) {
	char *header;
	size_t header_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &header, &header_len) == FAILURE) {
		RETURN_NULL();
	}
	zval *name_zv = sc_zend_read_property(Z_OBJCE_P(getThis()), getThis(), "name",
	                                      sizeof("name") - 1, 0);

	if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) {
		zend_throw_error(NULL, "Invalid or missing name property");
		RETURN_NULL();
	}

	sub_object *obj = table_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->bpf) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto table = obj->bpf->get_array_table<uint64_t>(Z_STRVAL_P(name_zv));
	auto res = table.get_table_offline();

	if (res.empty()) {
		std::cout << "empty histogram" << std::endl;
		RETURN_FALSE;
	}

	uint64_t max_val = *std::max_element(res.begin(), res.end());
	if (max_val == 0) max_val = 1;
	std::cout << "    " << std::left << std::setw(12) << header
	          << std::setw(10) << ": count"
	          << " distribution\n";


	int stars_max = 40;
	for (size_t i = 0; i < res.size(); ++i) {
		if (res[i] == 0) continue;

		std::string bar;
		int limit = std::min(stars_max, static_cast<int>((double) res[i] * stars_max / max_val));
		for (int j = 0; j < limit; ++j) bar += '*';
		if (res[i] > max_val && !bar.empty()) bar.back() = '+';

		std::string count_str = ": " + std::to_string(res[i]);
		std::cout << "    " << std::left << std::setw(12) << i
		          << std::setw(10) << count_str
		          << "|" << bar << "|\n";
	}
}

PHP_METHOD (PerCpuArrayTable, sum_value) {
	int64_t index;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &index) == FAILURE) {
		RETURN_NULL();
	}

	zval *name_zv = sc_zend_read_property(Z_OBJCE_P(getThis()), getThis(), "name",
	                                      sizeof("name") - 1, 0);


	if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) {
		zend_throw_error(NULL, "Invalid or missing name property");
		RETURN_NULL();
	}

	sub_object *obj = table_fetch_object(Z_OBJ_P(getThis()));

	if (!obj || !obj->bpf) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}


	std::vector<unsigned long> val;
	try {
		auto table = obj->bpf->get_percpu_array_table<uint64_t>(Z_STRVAL_P(name_zv));
		auto res = table.get_value(index, val);
		if (res.code() != 0) {
			zend_throw_error(NULL, "Get value error in %s", Z_STRVAL_P(name_zv));
			RETURN_NULL();
		}

		unsigned long long sum = 0;
		for (const auto &v: val) {
			sum += v;
		}

		RETURN_LONG(sum);
	} catch (const std::exception &e) {
		zend_throw_error(NULL, "Exception: %s", e.what());
		RETURN_NULL();
	}
}

PHP_METHOD (StackTraceTable, values) {
	zend_long stack_id;
	zend_long pid = -1;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|l", &stack_id, &pid) == FAILURE) {
		RETURN_NULL();
	}

	zval *name_zv = sc_zend_read_property(Z_OBJCE_P(getThis()), getThis(), "name",
	                                      sizeof("name") - 1, 0);

	if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) {
		zend_throw_error(NULL, "Invalid or missing name property");
		RETURN_NULL();
	}

	sub_object *obj = table_fetch_object(Z_OBJ_P(getThis()));
	if (!obj || !obj->bpf) {
		zend_throw_error(NULL, "Invalid object state");
		RETURN_NULL();
	}

	auto table = obj->bpf->get_stack_table(Z_STRVAL_P(name_zv));
	auto symbols = table.get_stack_symbol((int) stack_id, (int) pid);

	array_init(return_value);

	for (const auto &str: symbols) {
		add_next_index_string(return_value, str.c_str());
	}
}


/* }}} */
/* The previous line is meant for vim and emacs, so it can correctly fold and
   unfold functions in source code. See the corresponding marks just before
   function definition, where the functions purpose is also documented. Please
   follow this convention for the convenience of others editing your code.
*/


/* {{{ php_ebpf_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_ebpf_init_globals(zend_ebpf_globals *ebpf_globals)
{
	ebpf_globals->global_value = 0;
	ebpf_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ bpf_class_methods */
ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_construct, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, opts, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_get, 0, 0, 1)
    ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_get_kprobe_functions, 0, 0, 1)
    ZEND_ARG_INFO(0, fn)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_attach_kprobe, 0, 0, 2)
    ZEND_ARG_INFO(0, kernel_func)
    ZEND_ARG_INFO(0, probe_func)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_attach_tracepoint, 0, 0, 2)
    ZEND_ARG_INFO(0, tp_func)
    ZEND_ARG_INFO(0, probe_func)
ZEND_END_ARG_INFO()

#define arginfo_bpf_attach_raw_tracepoint arginfo_bpf_attach_tracepoint

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_attach_kfunc, 0, 0, 1)
    ZEND_ARG_INFO(0, kfunc)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_attach_lsm, 0, 0, 1)
    ZEND_ARG_INFO(0, lsm)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_attach_uprobe, 0, 0, 3)
    ZEND_ARG_INFO(0, binary_path)
    ZEND_ARG_INFO(0, symbol)
    ZEND_ARG_INFO(0, probe_func)
    ZEND_ARG_ARRAY_INFO(1, options, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_detach_kprobe, 0, 0, 1)
    ZEND_ARG_INFO(0, fn)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_detach_uprobe, 0, 0, 2)
    ZEND_ARG_INFO(0, binary_path)
    ZEND_ARG_INFO(0, symbol)
    ZEND_ARG_ARRAY_INFO(1, options, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_trace_print, 0, 0, 0)
    ZEND_ARG_INFO(0, fmt) // Optional
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_trace_fields, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_get_table, 0, 0, 1)
    ZEND_ARG_INFO(0, table_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_perf_buffer_poll, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_get_syscall_fnname, 0, 0, 1)
    ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_load_func, 0, 0, 2)
    ZEND_ARG_INFO(0, fn)
    ZEND_ARG_INFO(0, prog_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_bpf_attach_raw_socket, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, prog_fn, BPFProgFunction, 0)
    ZEND_ARG_INFO(0, interface)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for PerfEventArrayTable class */
ZEND_BEGIN_ARG_INFO_EX(arginfo_perf_event_array_table_open_perf_buffer, 0, 0, 1)
    ZEND_ARG_INFO(0, cb_fn_str)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for HashTable class */
ZEND_BEGIN_ARG_INFO_EX(arginfo_hash_table_values, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_hash_table_clear, 0, 0, 0)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for ArrayTable class */
ZEND_BEGIN_ARG_INFO_EX(arginfo_array_table_get_value, 0, 0, 1)
    ZEND_ARG_INFO(0, index)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_array_table_print_log2_hist, 0, 0, 1)
    ZEND_ARG_INFO(0, header)
ZEND_END_ARG_INFO()

#define arginfo_array_table_print_linear_hist arginfo_array_table_print_log2_hist
/* }}} */

/* {{{ arginfo for PerCpuArrayTable class */
ZEND_BEGIN_ARG_INFO_EX(arginfo_per_cpu_array_table_sum_value, 0, 0, 1)
    ZEND_ARG_INFO(0, index)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for StackTraceTable class */
ZEND_BEGIN_ARG_INFO_EX(arginfo_stack_trace_table_values, 0, 0, 1)
    ZEND_ARG_INFO(0, stack_id)
    ZEND_ARG_INFO(0, pid) // Optional
ZEND_END_ARG_INFO()
/* }}} */


/* {{{ PHP_INI
 */
/* Remove comments if you have entries in php.ini
PHP_INI_BEGIN()
    DISPLAY_INI_ENTRIES();
PHP_INI_END()
*/
/* }}} */

/* {{{ bpf_class_methods */
static const zend_function_entry bpf_class_methods[] = {
		PHP_ME(Bpf, __construct, arginfo_bpf_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
		PHP_ME(Bpf, __get, arginfo_bpf_get, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, get_kprobe_functions, arginfo_bpf_get_kprobe_functions, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, attach_kprobe, arginfo_bpf_attach_kprobe, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, attach_tracepoint, arginfo_bpf_attach_tracepoint, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, attach_raw_tracepoint, arginfo_bpf_attach_raw_tracepoint, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, attach_kfunc, arginfo_bpf_attach_kfunc, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, attach_lsm, arginfo_bpf_attach_lsm, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, attach_uprobe, arginfo_bpf_attach_uprobe, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, detach_kprobe, arginfo_bpf_detach_kprobe, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, detach_uprobe, arginfo_bpf_detach_uprobe, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, trace_print, arginfo_bpf_trace_print, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, trace_fields, arginfo_bpf_trace_fields, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, get_table, arginfo_bpf_get_table, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, perf_buffer_poll, arginfo_bpf_perf_buffer_poll, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, get_syscall_fnname, arginfo_bpf_get_syscall_fnname, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, load_func, arginfo_bpf_load_func, ZEND_ACC_PUBLIC)
	PHP_ME(Bpf, attach_raw_socket, arginfo_bpf_attach_raw_socket, ZEND_ACC_PUBLIC)
	PHP_FE_END
};
/* }}} */

/* {{{ table methods */
static const zend_function_entry perf_event_array_table_methods[] = {
	PHP_ME(PerfEventArrayTable, open_perf_buffer, arginfo_perf_event_array_table_open_perf_buffer, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

static const zend_function_entry hash_table_methods[] = {
	PHP_ME(HashTable, values, arginfo_hash_table_values, ZEND_ACC_PUBLIC)
	PHP_ME(HashTable, clear, arginfo_hash_table_clear, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

static const zend_function_entry array_table_methods[] = {
	PHP_ME(ArrayTable, get_value, arginfo_array_table_get_value, ZEND_ACC_PUBLIC)
	PHP_ME(ArrayTable, print_log2_hist, arginfo_array_table_print_log2_hist, ZEND_ACC_PUBLIC)
	PHP_ME(ArrayTable, print_linear_hist, arginfo_array_table_print_linear_hist, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

static const zend_function_entry prog_array_table_methods[] = {
	PHP_FE_END
};

static const zend_function_entry per_cpu_hash_table_methods[] = {
	PHP_FE_END
};

static const zend_function_entry per_cpu_array_table_methods[] = {
		PHP_ME(PerCpuArrayTable, sum_value, arginfo_per_cpu_array_table_sum_value, ZEND_ACC_PUBLIC)
		PHP_FE_END
};

static const zend_function_entry lpm_trie_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry stack_trace_table_methods[] = {
		PHP_ME(StackTraceTable, values, arginfo_stack_trace_table_values, ZEND_ACC_PUBLIC)
		PHP_FE_END
};

static const zend_function_entry lru_hash_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry lru_per_cpu_hash_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry cgroup_array_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry dev_map_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry cpu_map_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry xsk_map_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry map_in_map_array_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry map_in_map_hash_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry queue_stack_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry ring_buf_table_methods[] = {
		PHP_FE_END
};

static const zend_function_entry bpf_prog_func_methods[] = {
		PHP_FE_END
};
/* }}} */


PHP_MINIT_FUNCTION (ebpf) {
	zend_class_entry ce;

	memcpy(&bpf_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	bpf_object_handlers.offset = XtOffsetOf(bpf_object, std);
	bpf_object_handlers.free_obj = bpf_free_object;

	REGISTER_BPF_CLASS(ce, bpf_create_object, "Bpf", bpf_ce, bpf_class_methods)

	memcpy(&table_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	table_object_handlers.offset = XtOffsetOf(sub_object, std);
	table_object_handlers.free_obj = table_free_object;

	REGISTER_BPF_CLASS(ce, table_create_object, "PerCpuArrayTable", per_cpu_array_table_ce, per_cpu_array_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "PerfEventArrayTable", perf_event_array_table_ce,
	                   perf_event_array_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "HashTable", hash_table_ce, hash_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "ArrayTable", array_table_ce, array_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "ProgArrayTable", prog_array_table_ce, prog_array_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "PerCpuHashTable", per_cpu_hash_table_ce, per_cpu_hash_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "LpmTrieTable", lpm_trie_table_ce, lpm_trie_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "StackTraceTable", stack_trace_table_ce, stack_trace_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "LruHashTable", lru_hash_table_ce, lru_hash_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "LruPerCpuHashTable", lru_per_cpu_hash_table_ce,
	                   lru_per_cpu_hash_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "CgroupArrayTable", cgroup_array_table_ce, cgroup_array_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "DevMapTable", dev_map_table_ce, dev_map_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "CpuMapTable", cpu_map_table_ce, cpu_map_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "XskMapTable", xsk_map_table_ce, xsk_map_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "MapInMapArrayTable", map_in_map_array_table_ce,
	                   map_in_map_array_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "MapInMapHashTable", map_in_map_hash_table_ce,
	                   map_in_map_hash_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "QueueStackTable", queue_stack_table_ce, queue_stack_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "RingBufTable", ring_buf_table_ce, ring_buf_table_methods)
	REGISTER_BPF_CLASS(ce, table_create_object, "BPFProgFunction", bpf_prog_func_ce, bpf_prog_func_methods)

	/* Register constants */
	REGISTER_BPF_CONST(SOCKET_FILTER);
	REGISTER_BPF_CONST(KPROBE);
	REGISTER_BPF_CONST(SCHED_CLS);
	REGISTER_BPF_CONST(SCHED_ACT);
	REGISTER_BPF_CONST(TRACEPOINT);
	REGISTER_BPF_CONST(XDP);
	REGISTER_BPF_CONST(PERF_EVENT);
	REGISTER_BPF_CONST(CGROUP_SKB);
	REGISTER_BPF_CONST(CGROUP_SOCK);
	REGISTER_BPF_CONST(LWT_IN);
	REGISTER_BPF_CONST(LWT_OUT);
	REGISTER_BPF_CONST(LWT_XMIT);
	REGISTER_BPF_CONST(SOCK_OPS);
	REGISTER_BPF_CONST(SK_SKB);
	REGISTER_BPF_CONST(CGROUP_DEVICE);
	REGISTER_BPF_CONST(SK_MSG);
	REGISTER_BPF_CONST(RAW_TRACEPOINT);
	REGISTER_BPF_CONST(CGROUP_SOCK_ADDR);
	REGISTER_BPF_CONST(CGROUP_SOCKOPT);
	REGISTER_BPF_CONST(TRACING);
	REGISTER_BPF_CONST(LSM);
	return SUCCESS;
}


/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION (ebpf) {
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION (ebpf) {
#if defined(COMPILE_DL_EBPF) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION (ebpf) {
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION (ebpf) {
	php_info_print_table_start();
	php_info_print_table_header(2, "ebpf support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/* {{{ ebpf_functions[]
 *
 * Every user visible function must have an entry in ebpf_functions[].
 */
const zend_function_entry ebpf_functions[] = {
		PHP_FE_END    /* Must be the last line in ebpf_functions[] */
};
/* }}} */

/* {{{ ebpf_module_entry
 */
zend_module_entry ebpf_module_entry = {
		STANDARD_MODULE_HEADER,
		"ebpf",
		ebpf_functions,
		PHP_MINIT(ebpf),
		PHP_MSHUTDOWN(ebpf),
		PHP_RINIT(ebpf),        /* Replace with NULL if there's nothing to do at request start */
		PHP_RSHUTDOWN(ebpf),    /* Replace with NULL if there's nothing to do at request end */
		PHP_MINFO(ebpf),
		PHP_EBPF_VERSION,
		STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_EBPF
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(ebpf)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
