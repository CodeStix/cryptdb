import { CryptClient } from "cryptdb-client";

console.log("testing client");

const client = new CryptClient("TestingApp", "http://localhost:8080");

client.loginUsingPassword("stijnrogiest12", "Vrijdag1@").then(async (v) => {
    console.log("logged in", v);

    const group = await client.getGroup(v.personalGroupId);

    const collection = await client.getCollection(v.personalCollectionId);

    console.log("collection", collection);
    console.log("group", group);
});

// client.loginUsingPassword("stijnrogiest3", "Vrijdag1@").then((v) => {
//     console.log("logged in", v);
// });

// client.login("stijn rogiest").then((res) => {
//     console.log("logged in");
// });
