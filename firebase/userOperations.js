import { database } from "./firebaseConfig.js";

// Create a new user
export const createUser = async (userData) => {
    try {
        const newUserRef = database.ref('users').push();
        await newUserRef.set({
            ...userData,
            createdAt: new Date().toISOString()
        });
        return { id: newUserRef.key, ...userData };
    } catch (error) {
        console.error("Error creating user:", error);
        throw error;
    }
};

// Get all users
export const getAllUsers = async () => {
    try {
        const snapshot = await database.ref('users').once('value');
        if (snapshot.exists()) {
            const users = [];
            snapshot.forEach((childSnapshot) => {
                users.push({
                    id: childSnapshot.key,
                    ...childSnapshot.val()
                });
            });
            return users;
        }
        return [];
    } catch (error) {
        console.error("Error getting users:", error);
        throw error;
    }
};

// Get user by ID
export const getUserById = async (userId) => {
    try {
        const snapshot = await database.ref(`users/${userId}`).once('value');
        if (snapshot.exists()) {
            return {
                id: snapshot.key,
                ...snapshot.val()
            };
        }
        return null;
    } catch (error) {
        console.error("Error getting user:", error);
        throw error;
    }
};

// Update user
export const updateUser = async (userId, userData) => {
    try {
        const userRef = database.ref(`users/${userId}`);
        await userRef.update({
            ...userData,
            updatedAt: new Date().toISOString()
        });
        return { id: userId, ...userData };
    } catch (error) {
        console.error("Error updating user:", error);
        throw error;
    }
};

// Delete user
export const deleteUser = async (userId) => {
    try {
        await database.ref(`users/${userId}`).remove();
        return true;
    } catch (error) {
        console.error("Error deleting user:", error);
        throw error;
    }
}; 