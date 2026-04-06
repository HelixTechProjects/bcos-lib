// 数据头类型枚举
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TarsType {
    Char = 0,
    Short = 1,
    Int32 = 2,
    Int64 = 3,
    Float = 4,
    Double = 5,
    String1 = 6,
    String4 = 7,
    Map = 8,
    List = 9,
    StructBegin = 10,
    StructEnd = 11,
    ZeroTag = 12,
    SimpleList = 13,
}

// 最大字符串长度
pub const TARS_MAX_STRING_LENGTH: usize = 100 * 1024 * 1024;

pub struct TarsOutputStream {
    pub buf: Vec<u8>,
}

impl TarsOutputStream {
    pub fn new() -> Self {
        TarsOutputStream { buf: Vec::with_capacity(128) }
    }

    fn reserve_buf(&mut self, len: usize) {
        if self.buf.capacity() < len {
            let mut new_len = len * 2;
            if new_len < 128 {
                new_len = 128;
            }
            self.buf.reserve(new_len - self.buf.capacity());
        }
    }

    pub fn write_to_head(&mut self, t: TarsType, tag: u8) {
        let t = t as u8;
        if tag < 15 {
            self.buf.push(t + (tag << 4));
        } else {
            self.buf.push(t + 240);
            self.buf.push(tag);
        }
    }

    fn write_char_type_buf(&mut self, val: u8) {
        self.reserve_buf(self.buf.len() + 1);
        self.buf.push(val);
    }

    pub fn write_char(&mut self, n: u8, tag: u8) {
        if n == 0 {
            self.write_to_head(TarsType::ZeroTag, tag);
        } else {
            self.write_to_head(TarsType::Char, tag);
            self.write_char_type_buf(n);
        }
    }

    pub fn write_short(&mut self, n: i16, tag: u8) {
        if n >= -128 && n <= 127 {
            self.write_char(n as u8, tag);
        } else {
            self.write_to_head(TarsType::Short, tag);
   
            self.reserve_buf(self.buf.len() + 2);
            self.buf.extend_from_slice(&n.to_be_bytes());
        }
    }

    pub fn write_int32(&mut self, n: i32, tag: u8) {
        if n >= -32768 && n <= 32767 {
            self.write_short(n as i16, tag);
        } else {
            self.write_to_head(TarsType::Int32, tag);

            self.reserve_buf(self.buf.len() + 4);
            self.buf.extend_from_slice(&n.to_be_bytes());
        }
    }

    pub fn write_int64(&mut self, n: i64, tag: u8) {
        if n >= (-2147483647 - 1) && n <= 2147483647 {
            self.write_int32(n as i32, tag);
        } else {
            self.write_to_head(TarsType::Int64, tag);

            self.reserve_buf(self.buf.len() + 8);
            self.buf.extend_from_slice(&n.to_be_bytes());
        }
    }

    pub fn write_float(&mut self, n: f32, tag: u8) {
        self.write_to_head(TarsType::Float, tag);
        let val = n.to_bits(); // 等价于 tars_htonf
        self.reserve_buf(self.buf.len() + 4);
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    pub fn write_double(&mut self, n: f64, tag: u8) {
        self.write_to_head(TarsType::Double, tag);
        let val = n.to_bits(); // 等价于 tars_htond
        self.reserve_buf(self.buf.len() + 8);
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    pub fn write_string(&mut self, s: &str, tag: u8) {
        let len = s.len();
        if len > TARS_MAX_STRING_LENGTH {
            panic!("invalid string size, tag: {}, size: {}", tag, len);
        }

        if len > 255 {
            self.write_to_head(TarsType::String4, tag);
            self.reserve_buf(self.buf.len() + 4 + len);
            self.buf.extend_from_slice(&(len as u32).to_be_bytes());
        } else {
            self.write_to_head(TarsType::String1, tag);
            self.reserve_buf(self.buf.len() + 1 + len);
            self.buf.push(len as u8);
        }
        self.buf.extend_from_slice(s.as_bytes());
    }

    pub fn write_bytes(&mut self, data: &[u8], tag: u8) {
        self.write_to_head(TarsType::SimpleList, tag);
        self.write_to_head(TarsType::Char, 0);
        self.write_int32(data.len() as i32, 0);
        self.reserve_buf(self.buf.len() + data.len());
        self.buf.extend_from_slice(data);
    }

    pub fn write_unknown(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
    }

    pub fn write_unknown_v2(&mut self, s: &str) {
        self.write_to_head(TarsType::StructBegin, 0);
        self.buf.extend_from_slice(s.as_bytes());
        self.write_to_head(TarsType::StructEnd, 0);
    }

}
