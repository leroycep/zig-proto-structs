class TypeInfo {
    size() {
        throw new Error("Unimplemented");
    }

    read(dataview, ptr) {
        throw new Error("Unimplemented");
    }
}

class Int extends TypeInfo {
    constructor(signed, bits) {
        super();
        this.signed = signed;
        this.bits = bits;
    }

    size() {
        return Math.ceil(this.bits / 8);
    }

    read(dataview, ptr) {
        if (!this.signed && this.bits == 8) {
            return dataview.getUint8(ptr, true);
        } else if (!this.signed && this.bits == 32) {
            return dataview.getUint32(ptr, true);
        } else {
            throw new Error("Unimplemented");
        }
    }
}

class Slice extends TypeInfo {
    constructor(child) {
        super();
        this.child = child;
    }

    size() {
        return 8;
    }

    read(dataview, ptr) {
        const slice_ptr = dataview.getUint32(ptr, true);
        const slice_len = dataview.getUint32(ptr + 4, true);

        if (this.child instanceof Int && !this.child.signed && this.child.bits === 8) {
            return new Uint8Array(dataview.buffer, slice_ptr, slice_len);
        }

        const child_size = this.child.size();

        let array = [];
        for (let i = 0; i < slice_len; i += 1) {
            const child_ptr = slice_ptr + child_size * i;
            array.push(this.child.read(dataview, child_ptr));
        }

        return array;
    }
}

class Enum extends TypeInfo {
    constructor(props) {
        super();
        if (!(props.tag_type instanceof Int)) {
            throw new Error("Enum tag_type must be an Int");
        }
        this.tag_type = props.tag_type;
        if (!props.fields || props.fields.length == 0) {
            throw new Error("Enum must have at least one field");
        }
        this.fields = props.fields;

        this.values_to_fields = {};
        for (let field_name in this.fields) {
            const value = this.fields[field_name];
            this.values_to_fields[value] = field_name;
        }
    }

    size() {
        return this.tag_type.size();
    }

    read(dataview, ptr) {
        const value = this.tag_type.read(dataview, ptr);
        return this.values_to_fields[value];
    }
}

class Union extends TypeInfo {
    constructor(props) {
        super();
        if (!props.tag_type || !(props.tag_type instanceof Enum)) {
            throw new Error("Union tag_type must be an Enum");
        }
        this.tag_type = props.tag_type;
        if (!props.fields || props.fields.length == 0) {
            throw new Error("Union must have at least one field");
        }
        this.fields = props.fields;

        for (let field_name in this.fields) {
            if (this.tag_type.fields[field_name] === undefined) {
                throw new Error(
                    "Union contains field that tag_type does not: ",
                    field_name
                );
            }
        }
    }

    size() {
        let enum_size = this.tag_type.size();

        let child_size = 0;
        for (let field_name in this.fields) {
            const field_size = this.fields[field_name].size();
            if (field_size > child_size) {
                child_size = field_size;
            }
        }

        return enum_size + child_size;
    }

    read(dataview, ptr) {
        const tag_size = this.tag_type.size();
        const field_name = this.tag_type.read(dataview, ptr);

        const child_ptr = ptr + tag_size;
        const data = this.fields[field_name].read(dataview, child_ptr);

        return {
            tag: field_name,
            data: data,
        };
    }
}

let E = new Enum({
    tag_type: new Int(false, 8),
    fields: {
        integer: 0,
        text: 1,
    },
});

let U = new Union({
    tag_type: E,
    fields: {
        integer: new Int(false, 32),
        text: new Slice(new Int(false, 8)),
    },
});

console.log(U);
console.log(U.size());

class Decoder {
    constructor(typeInfo, bytes, ptr) {
        this.typeInfo = typeInfo;
        this.bytes = bytes;
        this.ptr = ptr || 0;
    }

    read() {
        return this.typeInfo.read(new DataView(this.bytes), this.ptr);
    }
}

function atob(a) {
    const buffer = Buffer.from(a, "base64");
    const arraybuffer = new ArrayBuffer(buffer.length);
    const array = new Uint8Array(arraybuffer);
    for (let i = 0; i < buffer.length; i += 1) {
        array[i] = buffer[i];
    }
    return arraybuffer;
}

let decoder = new Decoder(U, atob("ADkFAAAAAAAA"));
console.log(decoder.read());

decoder = new Decoder(U, atob("AQkAAAADAAAARm9v"));
const decoded = decoder.read();
console.log(decoded);
if (decoded.tag === "text") {
    console.log(new TextDecoder().decode(decoded.data));
}
