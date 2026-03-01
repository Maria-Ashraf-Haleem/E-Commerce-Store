import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema(
{
    name: {
    type: String,
    required: [true, "Please add a name"],
    trim: true
    },
    email: {
    type: String,
    required: [true, "Please add an email"],
    unique: true,
    lowercase: true,
    trim: true
    },
    password: {
    type: String,
    required: [true, "Please add a password"],
    minlength: [6, "Password must be at least 6 characters"]
    },
    cartItems: [
    {
        quantity: {
        type: Number,
        default: 1
        },
        product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product"
        }
    }
    ],
    role: {
    type: String,
    enum: ["customer", "admin"],
    default: "customer"
    }
},
{
    timestamps: true
}
);

userSchema.pre("save", async function () {

if (!this.isModified("password")) return;

const salt = await bcrypt.genSalt(10);
this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = async function (enteredPassword) {
return await bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.toJSON = function () {
const userObject = this.toObject();
delete userObject.password;
return userObject;
};
const User = mongoose.model("User", userSchema);
export default User;