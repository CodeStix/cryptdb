export type ServerMessage =
    // | {
    //       type: "auth";
    //       email: string;
    //   }
    | {
          type: "register";
          userName: string;

          authSaltBase64: string;
          authKeyBase64: string;

          encryptionSaltBase64: string;
          // Do not send encryptionKey!

          publicKeyBase64: string;
          encryptedPrivateKeyBase64: string;
          encryptedPrivateKeyNonceBase64: string;

          groupPublicKeyBase64: string;
          groupEncryptedPrivateKeyBase64: string;

          collectionPublicKeyBase64: string;
          collectionEncryptedPrivateKeyBase64: string;
          //   groupEncryptedPrivateKeyNonceBase64: string;
      }
    | {
          type: "get-user";
          userName: string;
      }
    | {
          type: "login";
          userName: string;
          authKeyBase64: string;
      }
    | {
          type: "insert";
          tableName: string;
          dataBase64: string;
          nonceBase64: string;
          publicData: any;
          collectionId: number;
          encryptedObjectKeyBase64: string;
          //   encryptedObjectKeyNonceBase64: string;
      }
    | {
          type: "share";
          tableName: string;
          id: number;
          collectionId: number;
          encryptedObjectKeyBase64: string;
      }
    | {
          type: "unshare";
          tableName: string;
          id: number;
          collectionId: number;
          // encryptedObjectKeyBase64: string;
      }
    | {
          type: "delete";
          tableName: string;
          id: number;
      }
    | {
          type: "create-collection";
          name: string;
          publicKeyBase64: string;
          selfEncryptedPrivateKeyBase64: string;
      }
    | {
          type: "get-collection";
          id: number;
      }
    | {
          type: "get-collections";
          name: string;
          //   inGroupId?: string;
      }
    | {
          type: "update";
          id: number;
          tableName: string;
          dataBase64?: string;
          nonceBase64?: string;
          publicData?: any;
      }
    | {
          type: "get";
          id: number;
          tableName: string;
          //   collectionId: number;
      }
    | {
          type: "query";
          tableName: string;
          collectionId: number;
          query: Record<string, any>;
      }
    | {
          type: "get-user-groups";
      }
    | {
          type: "upsert-table";
          tableName: string;
          description: TableColumnDescription[];
      }
    | {
          type: "create-group";
          groupName: string;
          publicKeyBase64: string;
          policies: GroupPolicyDescription[];
      }
    | {
          type: "update-group";
          groupId: number;
          policies: GroupPolicyDescription[];
      };

export type GroupPolicyDescription = {
    tableName: string;
    otherGroupId?: string;

    allowReadWrite?: boolean;
    writeFields?: string[];
    allowRead?: boolean;
    readFields?: string[];
    allowRemove?: boolean; // deleting or unsharing object from group
    allowAdd?: boolean; // adding or sharing object with group
};

export type TableColumnDescription =
    | {
          type: "TEXT";
          name: string;
          encrypted: boolean;
      }
    | {
          type: "INT";
          name: string;
          encrypted: boolean;
      }
    | {
          type: "BIGINT";
          name: string;
          encrypted: boolean;
      };

// type ServerRequestMessage = ServerMessage & { request: number };

export type ClientMessage =
    // | {
    //       type: "auth-response";
    //       request: number;
    //   }
    | {
          type: "create-collection-response";
          request: number;
          collectionId: number;
      }
    | {
          type: "get-collections-response";
          request: number;
          collections: {
              id: number;
              name: string;
              encryptedPrivateKeyBase64: string;
              publicKeyBase64: string;
              groupId: number;
          }[];
      }
    | {
          type: "get-collection-response";
          request: number;
          collection: {
              id: number;
              name: string;
              encryptedPrivateKeyBase64: string;
              publicKeyBase64: string;
              groupId: number;
          } | null;
      }
    | {
          type: "register-response";
          request: number;
      }
    | {
          type: "get-user-response";
          request: number;
          authSaltBase64?: string;
      }
    | {
          type: "login-response";
          request: number;

          publicKeyBase64: string;
          encryptedPrivateKeyNonceBase64: string;
          encryptedPrivateKeyBase64: string;
          encryptionSaltBase64: string;

          //   groupId: string;
          //   groupPublicKeyBase64: string;
          //   groupEncryptedPrivateKeyBase64: string;
          personalGroupId: number;
          personalCollectionId: number;
          groups: {
              id: number;
              publicKeyBase64: string;
              encryptedGroupPrivateKeyBase64: string;
              //   allowCreate: boolean;
              //   allowRead: boolean;
              //   allowWrite: boolean;
          }[];
      }
    | {
          type: "insert-response";
          request: number;
          //   version: number;
          id: number;
      }
    | {
          type: "update-invalid-version";
          request: number;
          nonceBase64: string;
          //   version: number;
      }
    | {
          type: "update-response";
          request: number;
      }
    | {
          type: "get-response";
          request: number;
          dataBase64?: string;
          nonceBase64?: string;
          publicData?: any;
          collectionId?: number;
          encryptedObjectKeyBase64?: string;
          //   encryptedObjectKeyNonceBase64?: string;
          //   version?: number;
      }
    | {
          type: "error-response";
          request: number;
          message: string;
      }
    | {
          type: "query-response";
          request: number;
          data: [
              id: number,
              dataBase64: string,
              nonceBase64: string,
              publicData: any,
              collectionId: number,
              encryptedObjectKeyBase64: string
              //   encryptedObjectKeyNonceBase64: string
          ][];
      }
    | {
          type: "get-user-groups-response";
          request: number;
          personalGroupId: number;
          groups: {
              id: number;
              publicKeyBase64: string;
              encryptedGroupPrivateKeyBase64: string;
              //   allowCreate: boolean;
              //   allowRead: boolean;
              //   allowWrite: boolean;
          }[];
      }
    | {
          type: "upsert-table-response";
          request: number;
      }
    | {
          type: "create-group-response";
          request: number;
          groupId: string;
      }
    | {
          type: "share-response";
          request: number;
      }
    | {
          type: "unshare-response";
          request: number;
      }
    | {
          type: "delete-response";
          request: number;
      };
