package com.supply.consumer;

import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateUtil;
import com.alibaba.fastjson.JSONObject;
import com.supply.constant.MessageConstant;
import com.supply.enumeration.EmailType;
import com.supply.exception.EmailTypeException;
import com.supply.utils.EmailUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Slf4j
@RequiredArgsConstructor
@Component
public class EmailConsumer {

    private final EmailUtil emailUtil;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(name = "email.queue"),
            exchange = @Exchange(name = "email.direct"),
            key = {"emailDirect"}
    ))
    public void listenDirect1Queue(String message) {
        log.info("接收到email.direct的消息：{}", message + "," + DateUtil.format(LocalDateTime.now(), DatePattern.NORM_DATETIME_PATTERN));
        EmailType emailType = EmailType.valueOf(JSONObject.parseObject(message).getString("emailType"));
        String email = JSONObject.parseObject(message).getString("emailAddress");
        if (emailType == EmailType.LOGIN) {
            String location = JSONObject.parseObject(message).getString("location");
            emailUtil.promptEmail(location, DateUtil.format(LocalDateTime.now(), DatePattern.NORM_DATETIME_PATTERN), email);
        } else if (emailType == EmailType.CHECK_SUCCESS) {
            Long adminId = JSONObject.parseObject(message).getLong("adminId");
            emailUtil.normalMail(email, String.format("你的账户信息审核已通过，立即可用。审核人编号：%d", adminId));
        } else if (emailType == EmailType.CHECK_FAILURE) {
            Long adminId = JSONObject.parseObject(message).getLong("adminId");
            emailUtil.normalMail(email, String.format("你的账户信息审核未通过，请重新提交。审核人编号：%d", adminId));
        } else if (emailType == EmailType.REPORT_BLOCKED) {
            String anotherEmailAddress = JSONObject.parseObject(message).getString("anotherEmailAddress");
            emailUtil.normalMail(email, """
                    你好，
                    经过我们的核实，发现你的举报对象确实存在违规行为，因而举报成立。
                    我们已对其采取封号措施，感谢你对供应系统做出的贡献。""");
            //再向被举报人发送邮件
            emailUtil.normalMail(anotherEmailAddress, """
                    你好，
                    你已被举报。经过我们的核实，发现你的账号确实存在违规行为。
                    我们已对你的账号进行封号处理，如有异议请联系管理人员。""");
        } else if (emailType == EmailType.REPORT_WARNING) {
            String anotherEmailAddress = JSONObject.parseObject(message).getString("anotherEmailAddress");
            emailUtil.normalMail(email, """
                    你好，
                    经过我们的核实，发现你的举报对象确实存在违规行为，因而举报成立。
                    我们已对其进行警告，并将持续关注，若发现其仍有违反规定的行为，将采取封号措施，感谢你对供应系统做出的贡献。""");
            emailUtil.normalMail(anotherEmailAddress, """
                    你好，
                    你已被举报。经过我们的核实，发现你的账号确实存在违规行为。
                    如果仍有违规行为，我们可能对你的账号进行封号处理，如有异议，请联系管理人员。""");
        } else if (emailType == EmailType.REPORT_FAILURE) {
            emailUtil.normalMail(email, """
                    你好，
                    经过我们的核实，发现你的举报对象暂时不存在违规行为，因而举报不成立。
                    我们将持续关注，若发现其有违反规定的行为，将采取警告或封号措施，感谢你对供应系统做出的贡献。""");
        }else{
            throw new EmailTypeException(MessageConstant.EMAIL_TYPE_ERROR);
        }
    }
}
