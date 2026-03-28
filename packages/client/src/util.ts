import { MessageInitShape, MessageShape } from "@bufbuild/protobuf";
import { ObjectValueSchema } from "./generated/protocol_pb";

export function valueToProtoValue(value: any): MessageInitShape<typeof ObjectValueSchema> | undefined {
    switch (typeof value) {
        case "boolean": {
            return { type: { case: "bool", value: value } };
        }
        case "number": {
            if (Number.isInteger(value)) {
                return { type: { case: "int", value: value } };
            } else {
                return { type: { case: "double", value: value } };
            }
        }
        case "bigint": {
            return { type: { case: "long", value: value } };
        }
        case "string": {
            return { type: { case: "string", value: value } };
        }
        case "undefined": {
            return undefined;
        }
        default: {
            console.error("Cannot serialize type", typeof value, name);
            return undefined;
        }
    }
}

export function objectToProtoObject(obj: any): { [key: string]: MessageInitShape<typeof ObjectValueSchema> } {
    const protoObj: { [key: string]: MessageInitShape<typeof ObjectValueSchema> } = {};

    const fields = Object.entries(obj);
    for (let i = 0; i < fields.length; i++) {
        const [name, value] = fields[i]!;
        const protoValue = valueToProtoValue(value);
        if (protoValue !== undefined) {
            protoObj[name] = protoValue;
        }
    }

    return protoObj;
}

export function protoValueToValue(protoValue: MessageShape<typeof ObjectValueSchema>) {
    return protoValue.type.value;
}

export function protoObjectToObject(
    protoObj: { [key: string]: MessageShape<typeof ObjectValueSchema> },
    obj: Record<string, number | string | boolean | bigint | Uint8Array> = {}
) {
    const protoFields = Object.entries(protoObj);
    for (let i = 0; i < protoFields.length; i++) {
        const [name, protoValue] = protoFields[i]!;
        const value = protoValueToValue(protoValue);
        if (value !== undefined) {
            obj[name] = value;
        }
    }

    return obj;
}

export function isEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }

    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }

    return true;
}
