import { database } from "./firebaseConfig.js";

// Create a new product
export const createProduct = async (productData) => {
    try {
        const newProductRef = database.ref('products').push();
        await newProductRef.set({
            ...productData,
            createdAt: new Date().toISOString()
        });
        return { id: newProductRef.key, ...productData };
    } catch (error) {
        console.error("Error creating product:", error);
        throw error;
    }
};

// Get all products
export const getAllProducts = async () => {
    try {
        const snapshot = await database.ref('products').once('value');
        if (snapshot.exists()) {
            const products = [];
            snapshot.forEach((childSnapshot) => {
                products.push({
                    id: childSnapshot.key,
                    ...childSnapshot.val()
                });
            });
            return products;
        }
        return [];
    } catch (error) {
        console.error("Error getting products:", error);
        throw error;
    }
};

// Get product by ID
export const getProductById = async (productId) => {
    try {
        const snapshot = await database.ref(`products/${productId}`).once('value');
        if (snapshot.exists()) {
            return {
                id: snapshot.key,
                ...snapshot.val()
            };
        }
        return null;
    } catch (error) {
        console.error("Error getting product:", error);
        throw error;
    }
};

// Update product
export const updateProduct = async (productId, productData) => {
    try {
        const productRef = database.ref(`products/${productId}`);
        await productRef.update({
            ...productData,
            updatedAt: new Date().toISOString()
        });
        return { id: productId, ...productData };
    } catch (error) {
        console.error("Error updating product:", error);
        throw error;
    }
};

// Delete product
export const deleteProduct = async (productId) => {
    try {
        await database.ref(`products/${productId}`).remove();
        return true;
    } catch (error) {
        console.error("Error deleting product:", error);
        throw error;
    }
}; 