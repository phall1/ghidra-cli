use std::ffi::c_int;

/// FFI function signature for bridge calls that take one string argument.
/// (pathPtr, pathLen, resultLenPtr) -> resultPtr
pub type FnOneArg = unsafe extern "system" fn(
    *const u8, // path ptr
    c_int,     // path len
    *mut c_int, // result len out
) -> *mut u8;

/// FFI function signature for bridge calls that take two string arguments.
/// (pathPtr, pathLen, arg2Ptr, arg2Len, resultLenPtr) -> resultPtr
pub type FnTwoArgs = unsafe extern "system" fn(
    *const u8, // path ptr
    c_int,     // path len
    *const u8, // arg2 ptr
    c_int,     // arg2 len
    *mut c_int, // result len out
) -> *mut u8;

/// FFI function signature for bridge calls that take three string arguments.
/// (pathPtr, pathLen, arg2Ptr, arg2Len, arg3Ptr, arg3Len, resultLenPtr) -> resultPtr
pub type FnThreeArgs = unsafe extern "system" fn(
    *const u8, // path ptr
    c_int,     // path len
    *const u8, // arg2 ptr
    c_int,     // arg2 len
    *const u8, // arg3 ptr
    c_int,     // arg3 len
    *mut c_int, // result len out
) -> *mut u8;

/// FFI function signature for FreeMem.
pub type FnFreeMem = unsafe extern "system" fn(*mut u8);

/// Call a one-arg bridge function and return the JSON string result.
pub unsafe fn call_one_arg(func: FnOneArg, free: FnFreeMem, arg1: &str) -> String {
    let mut result_len: c_int = 0;
    let result_ptr = func(
        arg1.as_ptr(),
        arg1.len() as c_int,
        &mut result_len,
    );
    read_and_free(result_ptr, result_len, free)
}

/// Call a two-arg bridge function and return the JSON string result.
pub unsafe fn call_two_args(
    func: FnTwoArgs,
    free: FnFreeMem,
    arg1: &str,
    arg2: &str,
) -> String {
    let mut result_len: c_int = 0;
    let result_ptr = func(
        arg1.as_ptr(),
        arg1.len() as c_int,
        arg2.as_ptr(),
        arg2.len() as c_int,
        &mut result_len,
    );
    read_and_free(result_ptr, result_len, free)
}

/// Call a three-arg bridge function and return the JSON string result.
pub unsafe fn call_three_args(
    func: FnThreeArgs,
    free: FnFreeMem,
    arg1: &str,
    arg2: &str,
    arg3: &str,
) -> String {
    let mut result_len: c_int = 0;
    let result_ptr = func(
        arg1.as_ptr(),
        arg1.len() as c_int,
        arg2.as_ptr(),
        arg2.len() as c_int,
        arg3.as_ptr(),
        arg3.len() as c_int,
        &mut result_len,
    );
    read_and_free(result_ptr, result_len, free)
}

/// Read a UTF-8 string from a pointer+length and free the memory.
unsafe fn read_and_free(ptr: *mut u8, len: c_int, free: FnFreeMem) -> String {
    if ptr.is_null() || len <= 0 {
        return String::from("{}");
    }
    let slice = std::slice::from_raw_parts(ptr, len as usize);
    let result = String::from_utf8_lossy(slice).into_owned();
    free(ptr);
    result
}
