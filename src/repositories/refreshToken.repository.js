import bcrypt from 'bcryptjs';
import RefreshToken from '../models/refreshtoken.model.js';

export const storeRefreshToken = async (userId, refreshToken, expiresAt) => {
    const tokenHash = await bcrypt.hash(refreshToken, 10);

    return RefreshToken.create({
        userId,
        tokenHash,
        expiresAt,
    });
};


export const findRefreshTokenByUserIdAndHash = async (userId, plainToken) => {
    const tokens = await RefreshToken.find({
        userId,
        revoked: false,
        expiresAt: { $gt: new Date() },
    }).sort({ createdAt: -1 });

    for (const tokenDoc of tokens) {
        const match = await bcrypt.compare(plainToken, tokenDoc.tokenHash);
        if (match) return tokenDoc;
    }

    return null;
};


export const revokeRefreshToken = async (tokenDoc) => {
    tokenDoc.revoked = true;
    await tokenDoc.save();
    return tokenDoc;
};

export const revokeAllUserRefreshTokens = async (userId) => {
    await RefreshToken.updateMany({ userId, revoked: false }, { revoked: true });
};