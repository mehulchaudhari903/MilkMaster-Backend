import { database } from "./firebaseConfig.js";

// Create a new contact message
export const createContactMessage = async (messageData) => {
    try {
        const newMessageRef = database.ref('contactMessages').push();
        await newMessageRef.set({
            ...messageData,
            status: 'unread',
            createdAt: new Date().toISOString()
        });
        return { id: newMessageRef.key, ...messageData };
    } catch (error) {
        console.error("Error creating contact message:", error);
        throw error;
    }
};

// Get all contact messages
export const getAllContactMessages = async () => {
    try {
        const snapshot = await database.ref('contactMessages').once('value');
        if (snapshot.exists()) {
            const messages = [];
            snapshot.forEach((childSnapshot) => {
                messages.push({
                    id: childSnapshot.key,
                    ...childSnapshot.val()
                });
            });
            return messages;
        }
        return [];
    } catch (error) {
        console.error("Error getting contact messages:", error);
        throw error;
    }
};

// Get contact message by ID
export const getContactMessageById = async (messageId) => {
    try {
        const snapshot = await database.ref(`contactMessages/${messageId}`).once('value');
        if (snapshot.exists()) {
            return {
                id: snapshot.key,
                ...snapshot.val()
            };
        }
        return null;
    } catch (error) {
        console.error("Error getting contact message:", error);
        throw error;
    }
};

// Update contact message status
export const updateContactMessageStatus = async (messageId, status) => {
    try {
        const messageRef = database.ref(`contactMessages/${messageId}`);
        await messageRef.update({
            status,
            updatedAt: new Date().toISOString()
        });
        return { id: messageId, status };
    } catch (error) {
        console.error("Error updating contact message:", error);
        throw error;
    }
};

// Delete contact message
export const deleteContactMessage = async (messageId) => {
    try {
        await database.ref(`contactMessages/${messageId}`).remove();
        return true;
    } catch (error) {
        console.error("Error deleting contact message:", error);
        throw error;
    }
};

// Get unread contact messages
export const getUnreadContactMessages = async () => {
    try {
        const snapshot = await database.ref('contactMessages')
            .orderByChild('status')
            .equalTo('unread')
            .once('value');
        
        if (snapshot.exists()) {
            const messages = [];
            snapshot.forEach((childSnapshot) => {
                messages.push({
                    id: childSnapshot.key,
                    ...childSnapshot.val()
                });
            });
            return messages;
        }
        return [];
    } catch (error) {
        console.error("Error getting unread messages:", error);
        throw error;
    }
}; 