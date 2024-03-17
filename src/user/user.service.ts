import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto, UpdateUserPasswordDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';
import { AuthUserDto } from './dto/auth-user.dto';
import { JwtService } from '@nestjs/jwt';
import { ClientProxy } from '@nestjs/microservices';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @Inject('AUTH_SERVICE') private client: ClientProxy,
    private jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<{ status: boolean }> {
    const find_email_or_username = await this.userModel
      .findOne({
        $or: [
          { email: createUserDto.email },
          { username: createUserDto.username },
        ],
      })
      .exec();
    if (find_email_or_username != null) throw new ConflictException();
    if (createUserDto.password != createUserDto.confirm_password)
      throw new BadRequestException('Password and Confirm Password not match');

    createUserDto.password = await bcrypt.hash(createUserDto.password, 10);
    const createdUser = new this.userModel(createUserDto);
    await createdUser.save();

    await this.client
      .emit('auth_user_register_queue', JSON.stringify(createdUser))
      .toPromise();

    return {
      status: true,
    };
  }

  async auth(authUserDto: AuthUserDto): Promise<{ access_token: string }> {
    const find_email_or_username = await this.userModel
      .findOne({
        $or: [
          { email: authUserDto.email_or_username },
          { username: authUserDto.email_or_username },
        ],
      })
      .exec();
    if (find_email_or_username == null) throw new UnauthorizedException();

    const isMatch = await bcrypt.compare(
      authUserDto.password,
      find_email_or_username.password,
    );
    if (!isMatch) throw new UnauthorizedException();

    const payload = {
      id: find_email_or_username._id,
      role: find_email_or_username.role,
    };
    const access_token = await this.jwtService.signAsync(payload);
    const hash = crypto.createHash('md5');
    hash.update(access_token);
    const access_token_hash = hash.digest('hex');

    const decoded = jwt.decode(access_token);

    await this.client
      .emit(
        'auth_access_token_hash_event',
        JSON.stringify({
          user: payload.id,
          access_token_hash,
          exp: decoded['exp'],
        }),
      )
      .toPromise();
    return {
      access_token,
    };
  }

  async verifyToken(token: string): Promise<any> {
    try {
      const decoded = await this.jwtService.verifyAsync(token);
      return decoded;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  async findOne(id: string): Promise<User> {
    return this.userModel.findById(id).exec();
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    const find_user = await this.userModel.findById(id).exec();

    const find_email_or_username = await this.userModel
      .find({
        email: { $not: { $eq: find_user.email } },
        username: { $not: { $eq: find_user.username } },
        $or: [
          { email: updateUserDto.email },
          { username: updateUserDto.username },
        ],
      })
      .exec();

    let email_exists = false;
    let username_exists = false;
    for (let index = 0; index < find_email_or_username.length; index++) {
      const element = find_email_or_username[index];
      if (element.email != find_user.email) {
        email_exists = true;
      }
      if (element.username != find_user.username) {
        username_exists = true;
      }
    }

    if (email_exists) throw new ConflictException('Email exists');
    if (username_exists) throw new ConflictException('Username exists');

    const updateUser = await this.userModel.findByIdAndUpdate(
      id,
      { ...updateUserDto, $inc: { __v: 1 } },
      {
        new: true,
      },
    );

    await this.client
      .emit('auth_user_update_queue', JSON.stringify(updateUser))
      .toPromise();

    return {
      status: true,
    };
  }

  async updatePassword(
    id: string,
    updateUserPasswordDto: UpdateUserPasswordDto,
  ) {
    if (
      updateUserPasswordDto.password != updateUserPasswordDto.confirm_password
    )
      throw new BadRequestException('Password and Confirm Password not match');

    updateUserPasswordDto.password = await bcrypt.hash(
      updateUserPasswordDto.password,
      10,
    );
    await this.userModel.findByIdAndUpdate(
      id,
      { ...updateUserPasswordDto, $inc: { __v: 1 } },
      {
        new: true,
      },
    );

    return {
      status: true,
    };
  }
}
