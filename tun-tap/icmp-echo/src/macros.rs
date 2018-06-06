/*
 * Reference:
 *  https://github.com/faern/rips/blob/master/packets/src/macros.rs
 *
 * Date: Apr 17 CST 2018
 */

macro_rules! packet {
    ($name:ident, $mut_name:ident, $min_len:expr) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
        pub struct $name<'a>(&'a [u8]);
        pub struct $mut_name<'a>(&'a mut [u8]);

        impl<'a> $name<'a> {
            #[allow(dead_code)]
            pub const MIN_LEN: usize = $min_len;

            #[inline]
            pub fn new(data: &'a [u8]) -> Option<$name<'a>> {
                if data.len() >= $min_len {
                    Some($name(data))
                } else {
                    None
                }
            }

            #[inline]
            pub fn data(&self) -> &[u8] {
                self.0
            }

        }

        impl<'a> $mut_name<'a> {
            
            #[inline]
            pub fn new(data: &'a mut [u8]) -> Option<$mut_name<'a>> {
                if data.len() >= $min_len {
                    Some($mut_name(data))
                } else {
                    None
                }
            }

            #[inline]
            pub fn as_immutable(&'a self) -> $name<'a> {
                $name(&self.0[..])
            }

            #[inline]
            pub fn data(&mut self) -> &mut [u8] {
                self.0
            }

        }
    }
}

macro_rules! getters {
    ($pkg:ident
     $(
         $(#[$doc: meta])*
         pub fn $name:ident(&$selff:ident) -> $type:ty $body:block
     )*) => {
        impl<'a> $pkg<'a> {
            $(
                $(#[$doc])*
                #[inline]
                pub fn $name(&$selff) -> $type {
                    $body
                }
            )*
        }
    }
}

macro_rules! setters {
    ($pkg:ident
     $(
         $(#[$doc: meta])*
         pub fn $name:ident(&mut $selff:ident, $arg:ident: $type:ty) $body:block
     )*) => {
        impl<'a> $pkg<'a> {
            $(
                $(#[$doc])*
                #[inline]
                pub fn $name(&mut $selff, $arg: $type) {
                    $body
                }
            )*
        }
    }
}

macro_rules! read_offset {
    ($buff:expr, $offset:expr, $type:ty) => {{
        let ptr = &$buff[$offset];
        unsafe { *(ptr as *const _ as *const $type) }
    }};
    ($buff:expr, $offset:expr, $type:ident, from_be) => {{
        $type::from_be(read_offset!($buff, $offset, $type))
    }}
}

macro_rules! write_offset {
    ($buff:expr, $offset:expr, $value:expr, $type:ty) => {{
        let ptr = (&mut $buff[$offset]) as *mut _ as *mut $type;
        unsafe { *ptr = $value };
    }};
    ($buff:expr, $offset:expr, $value:expr, $type:ident, to_be) => {{
        write_offset!($buff, $offset, $type::to_be($value), $type)
    }}
}
