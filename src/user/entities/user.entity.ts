import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

enum Role {
  ADMIN = 'admin',
  USER = 'user',
  GUEST = 'guest',
}

@Schema()
export class User {
  @Prop({ required: true, unique: true })
  username: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ default: Role.USER, enum: Role })
  role: Role;
}

export const UserSchema = SchemaFactory.createForClass(User);
