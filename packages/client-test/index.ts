import { CryptClient } from "cryptdb-client";

console.log("testing client");

const client = new CryptClient("TestingApp", "http://localhost:8080");

client.loginUsingPassword("stijnrogiest", "Vrijdag1@").then(async (v) => {
    console.log("logged in", v);

    const collection = await client.getCollection(client.personalCollectionId!);
    console.log("collection", collection);

    // const key = await collection.getKey(collection.getNewestKeyVersion());
    // console.log("key", key);

    // const group = await client.getGroup(client.personalGroupId!);
    // console.log("group", group);

    // const obj = await collection.createObjectRaw(
    //     "Test",
    //     {
    //         name: "stijn",
    //         age: 25,
    //     },
    //     {
    //         type: "person",
    //     }
    // );

    // const obj = await client.getObjectRaw("Test", 4n);
    // console.log("obj", obj);
    // const obj2 = await client.getObjectRaw("Test", 4n);
    // console.log(
    //     "obj2",
    //     JSON.stringify(obj2, (k, v) => (typeof v === "bigint" ? Number(v) : v))
    // );

    // const collection = await client.getCollection(v.personalCollectionId);
});

// client.loginUsingPassword("stijnrogiest3", "Vrijdag1@").then((v) => {
//     console.log("logged in", v);
// });

// client.login("stijn rogiest").then((res) => {
//     console.log("logged in");
// });
