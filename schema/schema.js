const User = require('../models/User');
const { GraphQLObjectType, GraphQLID, GraphQLString, GraphQLSchema, GraphQLList, GraphQLNonNull, GraphQLEnumType } = require('graphql')
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs')
dotenv.config({ path: '../config/config.env' });

const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: '3h',
  });
};

const AuthType = new GraphQLObjectType({
  name: 'Auth',
  fields: () => ({
    token: { type: GraphQLString },
  }),
});

const UserType = new GraphQLObjectType({
  name: 'User',
  fields: () => ({
    id: { type: GraphQLID },
    username: { type: GraphQLString },
    email: { type: GraphQLString },
    password: { type: GraphQLString },
  })
});


const RootQuery = new GraphQLObjectType({
  name: 'RootQueryType',
  fields: {
    users: {
      type: new GraphQLList(UserType),
      args: { id: { type: GraphQLID } },
      resolve(parent, args) {
        return User.find();
      }
    },
    user: {
      type: UserType,
      args: { id: { type: GraphQLID } },
      resolve(parent, args) {
        return User.findById(args.id)
      }
    },
  }
})

const mutation = new GraphQLObjectType({
  name: 'Mutation',
  fields: {
    signup: {
      type: AuthType,
      args: {
        username: { type: new GraphQLNonNull(GraphQLString) },
        email: { type: new GraphQLNonNull(GraphQLString) },
        password: { type: new GraphQLNonNull(GraphQLString) },
      },
      async resolve(parent, args) {
        const { username, email, password } = args;

        try {
          let user = await User.findOne({ email });

          if (user) {
            throw new Error('User already exists');
          }

          // Create a new user
          user = new User({
            username,
            email,
            password,
          });

          let salt = await bcrypt.genSalt(10);
          user.password = await bcrypt.hash(password, salt);

          await user.save();

          // Generate a JWT token upon successful signup
          const token = generateToken(user.id);
          return { user, token };
        } catch (err) {
          throw new Error(err.message);
        }
      },
    },
    login: {
      type: AuthType,
      args: {
        email: { type: new GraphQLNonNull(GraphQLString) },
        password: { type: new GraphQLNonNull(GraphQLString) },
      },
      async resolve(parent, args) {
        try {
          const user = await User.findOne({ email: args.email })
          if (!user) {
            throw new Error("User doesn't exists");
          }
          const token = generateToken(args.id);
          return { token };
        } catch (err) {
          // console.log(err)
          throw new Error(err.message);
        }
      },
    },
    updateUser: {
      type: UserType,
      args: {
        id: { type: new GraphQLNonNull(GraphQLID) },
        username: { type: GraphQLString },
        email: { type: GraphQLString },
        password: { type: GraphQLString },
        currentPassword: { type: GraphQLString },
      },
      async resolve(parent, args) {
        try {
          const { password, currentPassword, ...others } = args;
          const user = await User.findById(args.id);

          let newPassword;

          if (!user) {
            throw new Error("User doesn't exists");
          }
          // CHECK IF THE USER WANTS TO UPDATE THEIR PASSWORD
          if (args.password) {
            // IF CURRENT PASSWORD ISN'T GIVEN
            if (!args.currentPassword) {
              throw new Error("Provide your current password with 'currentPassword' before you can update your password");
            }
            let salt = await bcrypt.genSalt(10);
            newPassword = await bcrypt.hash(args.password, salt);
            const isMatch = await bcrypt.compare(currentPassword, user.password);
            if (!isMatch) {
              throw new Error("Old password isn't correct");
            }
          }
          return User.findByIdAndUpdate(
            args.id,
            {
              $set: {
                ...others,
                password: newPassword,
              },
            },
            { new: true }
          )
        } catch (err) {
          console.log(err)
          throw new Error(err.message);
        }
      }
    },
    deleteUser: {
      type: UserType,
      args: { id: { type: new GraphQLNonNull(GraphQLID) } },
      resolve(parent, args) {
        return User.findByIdAndDelete(args.id)
      }
    },
  }
})

module.exports = new GraphQLSchema({
  query: RootQuery,
  mutation
})