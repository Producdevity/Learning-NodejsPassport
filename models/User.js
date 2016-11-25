var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var Schema = mongoose.Schema;

// Create UserSchema
var UserSchema = new Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    index: {unique: true}
  },
  password: {
    type: String,
    required: true
    // select: false
  }
});

// UserSchema.pre('save', function(next){
//   var user = this;
//   if(!user.isModified('password')) return next();
//   console.log(user.isModified('password'));
//
//   bcrypt.hash(user.password, null, null, function(err, hash){
//     if(err) return next(err);
//     user.password = hash;
//     next();
//   });
//
// });
//
// // custom comparePassword method
// UserSchema.methods.comparePassword = function(password){
//   var user = this;
//   return bcrypt.compareSync(password, user.password);
// };

// Export the model schema.
var User = module.exports = mongoose.model('User', UserSchema);

module.exports.createUser = function(newUser, callback){
  bcrypt.genSalt(10, function(err, salt) {
    bcrypt.hash(newUser.password, salt, function(err, hash) {
      newUser.password = hash;
      newUser.save(callback);
    });
  });
};

module.exports.getUserByEmail = function(email, callback){
  var query = {email: email};
  User.findOne(query, callback);
};

module.exports.getUserById = function(id, callback){
  User.findById(id, callback);
};

module.exports.comparePassword = function(candidatePassword, hash, callback){
  bcrypt.compare(candidatePassword, hash, function(err, isMatch){
    if(err) throw err;
    callback(null, isMatch);
  });
};

