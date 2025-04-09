import { database } from "./firebaseConfig.js";

// Function to add dummy data
export const addDummyData = async () => {
    try {
        const dummyData = {
            users: {
                user1: {
                    name: "John Doe",
                    email: "john@example.com",
                    phone: "+1234567890",
                    address: "123 Main St",
                    role: "farmer"
                },
                user2: {
                    name: "Jane Smith",
                    email: "jane@example.com",
                    phone: "+1987654321",
                    address: "456 Oak Ave",
                    role: "distributor"
                }
            },
            milkCollections: {
                collection1: {
                    farmerId: "user1",
                    date: "2024-03-27",
                    quantity: 50,
                    price: 30,
                    status: "pending"
                },
                collection2: {
                    farmerId: "user1",
                    date: "2024-03-26",
                    quantity: 45,
                    price: 30,
                    status: "completed"
                }
            },
            payments: {
                payment1: {
                    collectionId: "collection1",
                    amount: 1500,
                    date: "2024-03-27",
                    status: "pending"
                },
                payment2: {
                    collectionId: "collection2",
                    amount: 1350,
                    date: "2024-03-26",
                    status: "completed"
                }
            }
        };

        await database.ref().set(dummyData);
        console.log("Dummy data added successfully!");
        return true;
    } catch (error) {
        console.error("Error adding dummy data:", error);
        return false;
    }
};

// Function to get all data
export const getAllData = async () => {
    try {
        const snapshot = await database.ref().once('value');
        if (snapshot.exists()) {
            return snapshot.val();
        } else {
            return null;
        }
    } catch (error) {
        console.error("Error getting data:", error);
        return null;
    }
}; 