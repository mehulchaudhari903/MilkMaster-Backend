import { database } from "./firebaseConfig.js";

// Create a new order
export const createOrder = async (orderData) => {
    try {
        const newOrderRef = database.ref('orders').push();
        await newOrderRef.set({
            ...orderData,
            status: 'pending',
            createdAt: new Date().toISOString()
        });
        return { id: newOrderRef.key, ...orderData };
    } catch (error) {
        console.error("Error creating order:", error);
        throw error;
    }
};

// Get all orders
export const getAllOrders = async () => {
    try {
        const snapshot = await database.ref('orders').once('value');
        if (snapshot.exists()) {
            const orders = [];
            snapshot.forEach((childSnapshot) => {
                orders.push({
                    id: childSnapshot.key,
                    ...childSnapshot.val()
                });
            });
            return orders;
        }
        return [];
    } catch (error) {
        console.error("Error getting orders:", error);
        throw error;
    }
};

// Get order by ID
export const getOrderById = async (orderId) => {
    try {
        const snapshot = await database.ref(`orders/${orderId}`).once('value');
        if (snapshot.exists()) {
            return {
                id: snapshot.key,
                ...snapshot.val()
            };
        }
        return null;
    } catch (error) {
        console.error("Error getting order:", error);
        throw error;
    }
};

// Update order
export const updateOrder = async (orderId, orderData) => {
    try {
        const orderRef = database.ref(`orders/${orderId}`);
        await orderRef.update({
            ...orderData,
            updatedAt: new Date().toISOString()
        });
        return { id: orderId, ...orderData };
    } catch (error) {
        console.error("Error updating order:", error);
        throw error;
    }
};

// Delete order
export const deleteOrder = async (orderId) => {
    try {
        await database.ref(`orders/${orderId}`).remove();
        return true;
    } catch (error) {
        console.error("Error deleting order:", error);
        throw error;
    }
};

// Get orders by user ID
export const getOrdersByUserId = async (userId) => {
    try {
        const snapshot = await database.ref('orders').orderByChild('userId').equalTo(userId).once('value');
        if (snapshot.exists()) {
            const orders = [];
            snapshot.forEach((childSnapshot) => {
                orders.push({
                    id: childSnapshot.key,
                    ...childSnapshot.val()
                });
            });
            return orders;
        }
        return [];
    } catch (error) {
        console.error("Error getting user orders:", error);
        throw error;
    }
}; 