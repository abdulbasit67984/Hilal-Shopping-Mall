import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";

export const verifyJWT = asyncHandler(async (req, _, next) => {
    
    if (process.env.NODE_ENV === 'development') {
        
        const user = await User.findOne().select("-password -refreshToken"); 
        console.log('user', user)
        req.user = user;  // Attach the user to the request
        return next();  // Skip further token verification and continue to the next handler
    }

    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            throw new ApiError(401, "Unauthorized access");
        }

        // Decode the token
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        // Find the user associated with the token
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken");

        if (!user) {
            throw new ApiError(401, "Invalid access token");
        }

        // Attach the user to the request
        req.user = user;
        next(); // Proceed to the next middleware or route handler

    } catch (error) {
        throw new ApiError(401, "Token verification failed");
    }
});
