pub unsafe fn any_as_u8_mut_slice<T: Sized>(p: &T) -> &mut [u8] {
    ::std::slice::from_raw_parts_mut((p as *const T) as *mut u8, ::std::mem::size_of::<T>())
}
