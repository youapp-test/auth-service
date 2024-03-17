import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  Put,
  UseGuards,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto, UpdateUserPasswordDto } from './dto/update-user.dto';
import { AuthUserDto } from './dto/auth-user.dto';
import { AuthGuard } from './auth.guard';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('register')
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  @Post('login')
  auth(@Body() authUserDto: AuthUserDto) {
    return this.userService.auth(authUserDto);
  }

  @Get()
  @UseGuards(AuthGuard)
  async verifyToken(@Req() req): Promise<any> {
    try {
      const user = await this.userService.findOne(req.user.id);
      return {
        _id: req.user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  @Put()
  @UseGuards(AuthGuard)
  update(@Req() req, @Body() updateUserDto: UpdateUserDto) {
    return this.userService.update(req.user.id, updateUserDto);
  }

  @Put('password')
  @UseGuards(AuthGuard)
  updatePassword(
    @Req() req,
    @Body() updateUserPasswordDto: UpdateUserPasswordDto,
  ) {
    return this.userService.updatePassword(req.user.id, updateUserPasswordDto);
  }
}
