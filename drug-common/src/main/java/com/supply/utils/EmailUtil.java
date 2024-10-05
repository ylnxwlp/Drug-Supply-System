package com.supply.utils;

import com.aliyuncs.utils.StringUtils;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;
import com.supply.constant.MessageConstant;

import java.util.Date;
import java.util.Random;
import java.util.UUID;


@Component
@Slf4j
@RequiredArgsConstructor
public class EmailUtil {

    private final JavaMailSenderImpl javaMailSender;


    @Value("${spring.mail.username}")
    private String sendMailer;


    public Integer codeMail(String to) {
        if (StringUtils.isEmpty(to)) {
            throw new RuntimeException(MessageConstant.EMAIL_RECEIVE_NULL);
        }
        Random r = new Random();
        int i = 100000 + r.nextInt(99999);
        String s = "您的验证码是：" + i + "\n" + "该验证码5分钟内有效，请勿泄露";
        sendMail(to, s);
        return i;
    }


    public void normalMail(String to, String text) {
        if (StringUtils.isEmpty(to)) {
            throw new RuntimeException(MessageConstant.EMAIL_RECEIVE_NULL);
        }
        if (StringUtils.isEmpty(text)) {
            throw new RuntimeException(MessageConstant.EMAIL_CONTENT_NULL);
        }

        sendMail(to, text);
    }

    public void promptEmail(String location, String time, String to) {
        if (StringUtils.isEmpty(to)) {
            throw new RuntimeException(MessageConstant.EMAIL_RECEIVE_NULL);
        }
        sendPromptEmail(location, time,to);
    }




    private void sendMail(String to, String text) {
        String content = "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "<meta charset=\"utf-8\">\n" +
                "<title>药品供应管理系统</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "\t<h3> " + text + "</h3>\n" +
                "<br></br>" +
                "</body>\n" +
                "</html>";
        try {
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(javaMailSender.createMimeMessage(), true);
            mimeMessageHelper.setFrom(sendMailer);
            mimeMessageHelper.setTo(to.split(","));
            mimeMessageHelper.setSubject(UUID.randomUUID().toString());
            mimeMessageHelper.setText(content, true);
            mimeMessageHelper.setSentDate(new Date());

            //发送邮件
            javaMailSender.send(mimeMessageHelper.getMimeMessage());
            log.info("发送邮件成功：{}->{}", sendMailer, to);

        } catch (MessagingException e) {
            e.printStackTrace();
            log.error("发送邮件失败：{}", e.getMessage());
        }
    }

    private void sendPromptEmail(String location, String time, String to) {
        String content = "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "<meta charset=\"utf-8\">\n" +
                "<title>药品供应管理系统</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "\t<h1> " + "药品供应管理系统" + "</h1>\n" +
                "\t<h3> " + " <药品供应管理系统>最近登录提醒：你于" + time + "在" + location + "进行了登录操作，如果不是你本人操作，请联系管理人员处理" + "</h1>\n" +
                "<br></br>" +
                "</body>\n" +
                "</html>";
        try {
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(javaMailSender.createMimeMessage(), true);
            mimeMessageHelper.setFrom(sendMailer);
            mimeMessageHelper.setTo(to.split(","));
            mimeMessageHelper.setSubject(UUID.randomUUID().toString());
            mimeMessageHelper.setText(content, true);
            mimeMessageHelper.setSentDate(new Date());

            //发送邮件
            javaMailSender.send(mimeMessageHelper.getMimeMessage());
            log.info("发送邮件成功：{}->{}", sendMailer, to);

        } catch (MessagingException e) {
            e.printStackTrace();
            log.error("发送邮件失败：{}", e.getMessage());
        }
    }
}


