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
    required: true,
    select: false
  }
});

UserSchema.pre('save', function(next){
  var user = this;
  if(!user.isModified('password')) return next();
  console.log(user.isModified('password'));

  bcrypt.hash(user.password, null, null, function(err, hash){
    if(err) return next(err);
    user.password = hash;
    next();
  });

});

// custom comparePassword method
UserSchema.methods.comparePassword = function(password){
  var user = this;
  return bcrypt.compareSync(password, user.password);
};

// Export the model schema.
module.exports = mongoose.model('user', UserSchema);
